package overlay

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/ns"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/resolvconf"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

var (
	hostMode    bool                      // overlay驱动中vxlan是否为host模式
	networkOnce sync.Once                 // 整个overlay 驱动在运行过程中，只需要运行一次networkOnce
	networkMu   sync.Mutex                // 访问vniTbl列表时，需要上锁，线程需要安全
	vniTbl      = make(map[uint32]string) // 全局的overlay驱动存储的vni表，key为vni值，value为一个路径
)

type networkTable map[string]*network // 整个overlay驱动拥有的网络列表

type subnet struct {
	once      *sync.Once
	vxlanName string     // vxlan 名称
	brName    string     // 网桥名称
	vni       uint32     // vxlan network identifier, 每一个子网有一个vni
	initErr   error      // 子网初始化错误
	subnetIP  *net.IPNet // 子网的网络地址，子网包含网络IP地址，以及网络掩码
	gwIP      *net.IPNet // 子网的网关地址
}

type subnetJSON struct {
	SubnetIP string
	GwIP     string
	Vni      uint32
}

// 这个network属于通过overlay网络驱动创建出来的network，存储在driver中的networkTable
// 每个具体的driver都会有对应的network列表
// 与controller中的network结构体不一样，那是一个全局的network，不分类型，包含统一的信息
type network struct {
	id        string
	dbIndex   uint64
	dbExists  bool
	sbox      osl.Sandbox   // 每一个network都会有相对应的sandbox
	endpoints endpointTable // overlay网络中藏有的endpoint列表
	driver    *driver       // overlay网络指向的驱动
	joinCnt   int           // overlay网络有多少次endpoint加入进来
	once      *sync.Once    // 每一个网络需要做一个初始化initSandbox的工作
	initEpoch int           //
	initErr   error         // 看network在初始化过程中是否出错
	subnets   []*subnet     // overlay网络中包含的子网
	secure    bool          // 是否需要对该overlay网络进行ipsec加密
	mtu       int           // 为overlay网络设定最大传输单元
	sync.Mutex
}

func (d *driver) NetworkAllocate(id string, option map[string]string, ipV4Data, ipV6Data []driverapi.IPAMData) (map[string]string, error) {
	return nil, types.NotImplementedErrorf("not implemented")
}

func (d *driver) NetworkFree(id string) error {
	return types.NotImplementedErrorf("not implemented")
}

func (d *driver) CreateNetwork(id string, option map[string]interface{}, nInfo driverapi.NetworkInfo, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	if id == "" {
		return fmt.Errorf("invalid network id")
	}
	if len(ipV4Data) == 0 || ipV4Data[0].Pool.String() == "0.0.0.0/0" {
		return types.BadRequestErrorf("ipv4 pool is empty")
	}

	// Since we perform lazy configuration make sure we try
	// configuring the driver when we enter CreateNetwork
	// 假如driver的 vxlan id没有配置，则需要先配置
	if err := d.configure(); err != nil {
		return err
	}

	n := &network{
		id:        id,
		driver:    d,
		endpoints: endpointTable{},
		once:      &sync.Once{},
		subnets:   []*subnet{},
	}

	vnis := make([]uint32, 0, len(ipV4Data))

	// if gval, ok := option["com.docker.network.generic"]; ok {
	if gval, ok := option[netlabel.GenericData]; ok {
		optMap := gval.(map[string]string)
		// if val, ok := optMap["com.docker.network.driver.overlay.vxlanid_list"]
		// 说明用户可以通过options来为输入vxlan ID
		if val, ok := optMap[netlabel.OverlayVxlanIDList]; ok {
			logrus.Debugf("overlay: Received vxlan IDs: %s", val)
			vniStrings := strings.Split(val, ",")
			for _, vniStr := range vniStrings {
				vni, err := strconv.Atoi(vniStr)
				if err != nil {
					return fmt.Errorf("invalid vxlan id value %q passed", vniStr)
				}

				vnis = append(vnis, uint32(vni))
			}
		}
		if _, ok := optMap["encrypted"]; ok {
			n.secure = true
		}

		// optMap["com.docker.network.driver.mtu"]
		if val, ok := optMap[netlabel.DriverMTU]; ok {
			var err error
			if n.mtu, err = strconv.Atoi(val); err != nil {
				return fmt.Errorf("failed to parse %v: %v", val, err)
			}
			if n.mtu < 0 {
				return fmt.Errorf("invalid MTU value: %v", n.mtu)
			}
		}
	}

	// If we are getting vnis from libnetwork, either we get for
	// all subnets or none.
	if len(vnis) != 0 && len(vnis) < len(ipV4Data) {
		// 如果输入的vni个数少于ipV4Data, 那么就抛出不足的错误。
		// 如果输入的vni个数大于的话，岂不是不予处理
		return fmt.Errorf("insufficient vnis(%d) passed to overlay", len(vnis))
	}

	// 根据ipV4Data的个数来创建network中的子网个数
	for i, ipd := range ipV4Data {
		s := &subnet{
			subnetIP: ipd.Pool,
			gwIP:     ipd.Gateway,
			once:     &sync.Once{},
		}

		if len(vnis) != 0 {
			s.vni = vnis[i]
		}

		n.subnets = append(n.subnets, s)
	}

	if err := n.writeToStore(); err != nil {
		return fmt.Errorf("failed to update data store for network %v: %v", n.id, err)
	}

	// Make sure no rule is on the way from any stale secure network
	if !n.secure {
		for _, vni := range vnis {
			programMangle(vni, false)
			programInput(vni, false)
		}
	}

	if nInfo != nil {
		// ovPeerTable = "overlay_peer_table"
		if err := nInfo.TableEventRegister(ovPeerTable, driverapi.EndpointObject); err != nil {
			return err
		}
	}

	// 仅仅将network加入driver的列表中
	// 创建一个网络而已，不会涉及到任何容器，endpoint等信息。
	d.addNetwork(n)
	return nil
}

func (d *driver) DeleteNetwork(nid string) error {
	if nid == "" {
		return fmt.Errorf("invalid network id")
	}

	// Make sure driver resources are initialized before proceeding
	if err := d.configure(); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("could not find network with id %s", nid)
	}

	// 删除网络前，需要关心network关联的endpoint应该解除联系
	for _, ep := range n.endpoints {
		if ep.ifName != "" {
			if link, err := ns.NlHandle().LinkByName(ep.ifName); err != nil {
				ns.NlHandle().LinkDel(link)
			}
		}

		if err := d.deleteEndpointFromStore(ep); err != nil {
			logrus.Warnf("Failed to delete overlay endpoint %s from local store: %v", ep.id[0:7], err)
		}

	}
	d.deleteNetwork(nid)

	vnis, err := n.releaseVxlanID()
	if err != nil {
		return err
	}

	if n.secure {
		for _, vni := range vnis {
			programMangle(vni, false)
			programInput(vni, false)
		}
	}

	return nil
}

func (d *driver) ProgramExternalConnectivity(nid, eid string, options map[string]interface{}) error {
	return nil
}

func (d *driver) RevokeExternalConnectivity(nid, eid string) error {
	return nil
}

func (n *network) incEndpointCount() {
	n.Lock()
	defer n.Unlock()
	n.joinCnt++
}

func (n *network) joinSandbox(restore bool) error {
	// If there is a race between two go routines here only one will win
	// the other will wait.
	n.once.Do(func() {
		// save the error status of initSandbox in n.initErr so that
		// all the racing go routines are able to know the status.
		n.initErr = n.initSandbox(restore)
	})

	return n.initErr
}

func (n *network) joinSubnetSandbox(s *subnet, restore bool) error {
	s.once.Do(func() {
		s.initErr = n.initSubnetSandbox(s, restore)
	})
	return s.initErr
}

func (n *network) leaveSandbox() {
	n.Lock()
	defer n.Unlock()
	n.joinCnt--
	if n.joinCnt != 0 {
		return
	}

	// We are about to destroy sandbox since the container is leaving the network
	// Reinitialize the once variable so that we will be able to trigger one time
	// sandbox initialization(again) when another container joins subsequently.
	n.once = &sync.Once{}
	for _, s := range n.subnets {
		s.once = &sync.Once{}
	}

	n.destroySandbox()
}

// to be called while holding network lock
func (n *network) destroySandbox() {
	if n.sbox != nil {
		for _, iface := range n.sbox.Info().Interfaces() {
			if err := iface.Remove(); err != nil {
				logrus.Debugf("Remove interface %s failed: %v", iface.SrcName(), err)
			}
		}

		for _, s := range n.subnets {
			if hostMode {
				if err := removeFilters(n.id[:12], s.brName); err != nil {
					logrus.Warnf("Could not remove overlay filters: %v", err)
				}
			}

			if s.vxlanName != "" {
				err := deleteInterface(s.vxlanName)
				if err != nil {
					logrus.Warnf("could not cleanup sandbox properly: %v", err)
				}
			}
		}

		if hostMode {
			if err := removeNetworkChain(n.id[:12]); err != nil {
				logrus.Warnf("could not remove network chain: %v", err)
			}
		}

		n.sbox.Destroy()
		n.sbox = nil
	}
}

func populateVNITbl() {
	// 遍历路径filepath.Dir(osl.GenerateKey("walk"))下的所有文件，并执行相应的WalkFunc
	//
	filepath.Walk(filepath.Dir(osl.GenerateKey("walk")),
		func(path string, info os.FileInfo, err error) error {
			_, fname := filepath.Split(path)

			if len(strings.Split(fname, "-")) <= 1 {
				return nil
			}

			ns, err := netns.GetFromPath(path)
			if err != nil {
				logrus.Errorf("Could not open namespace path %s during vni population: %v", path, err)
				return nil
			}
			defer ns.Close()

			nlh, err := netlink.NewHandleAt(ns, syscall.NETLINK_ROUTE)
			if err != nil {
				logrus.Errorf("Could not open netlink handle during vni population for ns %s: %v", path, err)
				return nil
			}
			defer nlh.Delete()

			err = nlh.SetSocketTimeout(soTimeout)
			if err != nil {
				logrus.Warnf("Failed to set the timeout on the netlink handle sockets for vni table population: %v", err)
			}

			links, err := nlh.LinkList()
			if err != nil {
				logrus.Errorf("Failed to list interfaces during vni population for ns %s: %v", path, err)
				return nil
			}

			for _, l := range links {
				if l.Type() == "vxlan" {
					vniTbl[uint32(l.(*netlink.Vxlan).VxlanId)] = path
				}
			}

			return nil
		})
}

func networkOnceInit() {
	// 基本上属于将原有的vni放入overlay全局的vni列表中
	populateVNITbl()

	if os.Getenv("_OVERLAY_HOST_MODE") != "" {
		hostMode = true
		return
	}

	// 在overlay驱动的第一次初始化过程中，尝试创建一个测试版的vxlan网络接口
	err := createVxlan("testvxlan", 1, 0)
	if err != nil {
		logrus.Errorf("Failed to create testvxlan interface: %v", err)
		return
	}

	// 保证在初始化过程中，推出之前会删除这个测试版的vxlan的网络接口
	defer deleteInterface("testvxlan")

	path := "/proc/self/ns/net"
	hNs, err := netns.GetFromPath(path)
	if err != nil {
		logrus.Errorf("Failed to get network namespace from path %s while setting host mode: %v", path, err)
		return
	}
	defer hNs.Close()

	nlh := ns.NlHandle()

	iface, err := nlh.LinkByName("testvxlan")
	if err != nil {
		logrus.Errorf("Failed to get link testvxlan while setting host mode: %v", err)
		return
	}

	// If we are not able to move the vxlan interface to a namespace
	// then fallback to host mode
	if err := nlh.LinkSetNsFd(iface, int(hNs)); err != nil {
		hostMode = true
	}
}

// 为一个子网生成Vxlan的名字
// 名字的形式为 vx-aaaaaa-bbbbb,
func (n *network) generateVxlanName(s *subnet) string {
	id := n.id
	if len(n.id) > 5 {
		id = n.id[:5]
	}

	return "vx-" + fmt.Sprintf("%06x", n.vxlanID(s)) + "-" + id
}

// 为一个子网声称网桥的名字
// 形式为 ov-aaaaaa-bbbbb
func (n *network) generateBridgeName(s *subnet) string {
	id := n.id
	if len(n.id) > 5 {
		id = n.id[:5]
	}

	return n.getBridgeNamePrefix(s) + "-" + id
}

// 形式为 ov-aaaaa
func (n *network) getBridgeNamePrefix(s *subnet) string {
	return "ov-" + fmt.Sprintf("%06x", n.vxlanID(s))
}

func checkOverlap(nw *net.IPNet) error {
	var nameservers []string

	if rc, err := resolvconf.Get(); err == nil {
		nameservers = resolvconf.GetNameserversAsCIDR(rc.Content)
	}

	if err := netutils.CheckNameserverOverlaps(nameservers, nw); err != nil {
		return fmt.Errorf("overlay subnet %s failed check with nameserver: %v: %v", nw.String(), nameservers, err)
	}

	if err := netutils.CheckRouteOverlaps(nw); err != nil {
		return fmt.Errorf("overlay subnet %s failed check with host route table: %v", nw.String(), err)
	}

	return nil
}

func (n *network) restoreSubnetSandbox(s *subnet, brName, vxlanName string) error {
	sbox := n.sandbox()

	// restore overlay osl sandbox
	Ifaces := make(map[string][]osl.IfaceOption)
	brIfaceOption := make([]osl.IfaceOption, 2)
	brIfaceOption = append(brIfaceOption, sbox.InterfaceOptions().Address(s.gwIP))
	brIfaceOption = append(brIfaceOption, sbox.InterfaceOptions().Bridge(true))
	Ifaces[fmt.Sprintf("%s+%s", brName, "br")] = brIfaceOption

	err := sbox.Restore(Ifaces, nil, nil, nil)
	if err != nil {
		return err
	}

	Ifaces = make(map[string][]osl.IfaceOption)
	vxlanIfaceOption := make([]osl.IfaceOption, 1)
	vxlanIfaceOption = append(vxlanIfaceOption, sbox.InterfaceOptions().Master(brName))
	Ifaces[fmt.Sprintf("%s+%s", vxlanName, "vxlan")] = vxlanIfaceOption
	err = sbox.Restore(Ifaces, nil, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (n *network) setupSubnetSandbox(s *subnet, brName, vxlanName string) error {

	if hostMode {
		// Try to delete stale bridge interface if it exists
		if err := deleteInterface(brName); err != nil {
			deleteInterfaceBySubnet(n.getBridgeNamePrefix(s), s)
		}
		// Try to delete the vxlan interface by vni if already present
		deleteVxlanByVNI("", n.vxlanID(s))

		if err := checkOverlap(s.subnetIP); err != nil {
			return err
		}
	}

	if !hostMode {
		// Try to find this subnet's vni is being used in some
		// other namespace by looking at vniTbl that we just
		// populated in the once init. If a hit is found then
		// it must a stale namespace from previous
		// life. Destroy it completely and reclaim resourced.
		networkMu.Lock()
		path, ok := vniTbl[n.vxlanID(s)]
		networkMu.Unlock()

		if ok {
			deleteVxlanByVNI(path, n.vxlanID(s))
			if err := syscall.Unmount(path, syscall.MNT_FORCE); err != nil {
				logrus.Errorf("unmount of %s failed: %v", path, err)
			}
			os.Remove(path)

			networkMu.Lock()
			delete(vniTbl, n.vxlanID(s))
			networkMu.Unlock()
		}
	}

	// create a bridge and vxlan device for this subnet and move it to the sandbox
	sbox := n.sandbox()

	if err := sbox.AddInterface(brName, "br",
		sbox.InterfaceOptions().Address(s.gwIP),
		sbox.InterfaceOptions().Bridge(true)); err != nil {
		return fmt.Errorf("bridge creation in sandbox failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	err := createVxlan(vxlanName, n.vxlanID(s), n.maxMTU())
	if err != nil {
		return err
	}

	if err := sbox.AddInterface(vxlanName, "vxlan",
		sbox.InterfaceOptions().Master(brName)); err != nil {
		return fmt.Errorf("vxlan interface creation failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	if hostMode {
		if err := addFilters(n.id[:12], brName); err != nil {
			return err
		}
	}

	return nil
}

// 一个network中有可能有多个subnet子网
// initSubnetSandbox实现将这个subnet子网内部的所有的初始化工作
func (n *network) initSubnetSandbox(s *subnet, restore bool) error {
	brName := n.generateBridgeName(s)   // ov-aaaaaa-bbbbb
	vxlanName := n.generateVxlanName(s) // ox-aaaaaa-bbbbb

	if restore {
		// 完成网络的Sandbox内的网络接口restore，
		// 包括将网络接口启动，重启还需要完成网络路由规则的初始化
		if err := n.restoreSubnetSandbox(s, brName, vxlanName); err != nil {
			return err
		}
	} else {
		if err := n.setupSubnetSandbox(s, brName, vxlanName); err != nil {
			return err
		}
	}

	n.Lock()
	// 为一个子网创建vxlan的名字以及网桥的名称
	s.vxlanName = vxlanName
	s.brName = brName
	n.Unlock()

	return nil
}

func (n *network) cleanupStaleSandboxes() {
	filepath.Walk(filepath.Dir(osl.GenerateKey("walk")),
		func(path string, info os.FileInfo, err error) error {
			_, fname := filepath.Split(path)

			pList := strings.Split(fname, "-")
			if len(pList) <= 1 {
				return nil
			}

			pattern := pList[1]
			if strings.Contains(n.id, pattern) {
				// Delete all vnis
				deleteVxlanByVNI(path, 0)
				syscall.Unmount(path, syscall.MNT_DETACH)
				os.Remove(path)

				// Now that we have destroyed this
				// sandbox, remove all references to
				// it in vniTbl so that we don't
				// inadvertently destroy the sandbox
				// created in this life.
				networkMu.Lock()
				for vni, tblPath := range vniTbl {
					if tblPath == path {
						delete(vniTbl, vni)
					}
				}
				networkMu.Unlock()
			}

			return nil
		})
}

// 每一个network网络都需要实现sandbox的初始化
func (n *network) initSandbox(restore bool) error {
	n.Lock()
	n.initEpoch++
	n.Unlock()

	// 整个overlay 驱动在运行过程中，只需要运行一次networkOnce，
	// 1. 以保障每个engine上的vxlan网络是可以用来创建的；
	// 2. 同时将机器上现有的vxlan网络接管到overlay网络的vni列表中
	networkOnce.Do(networkOnceInit)

	if !restore {
		if hostMode {
			// 将该网络的network id添加到iptables链中
			if err := addNetworkChain(n.id[:12]); err != nil {
				return err
			}
		}

		// If there are any stale sandboxes related to this network
		// from previous daemon life clean it up here
		n.cleanupStaleSandboxes()
	}

	// In the restore case network sandbox already exist; but we don't know
	// what epoch number it was created with. It has to be retrieved by
	// searching the net namespaces.
	key := ""
	if restore {
		key = osl.GenerateKey("-" + n.id)
	} else {
		key = osl.GenerateKey(fmt.Sprintf("%d-", n.initEpoch) + n.id)
	}

	sbox, err := osl.NewSandbox(key, !hostMode, restore)
	if err != nil {
		return fmt.Errorf("could not get network sandbox (oper %t): %v", restore, err)
	}

	// 将这个network的Sandbox赋值
	n.setSandbox(sbox)

	if !restore {
		n.driver.peerDbUpdateSandbox(n.id)
	}

	var nlSock *nl.NetlinkSocket
	sbox.InvokeFunc(func() {
		nlSock, err = nl.Subscribe(syscall.NETLINK_ROUTE, syscall.RTNLGRP_NEIGH)
	})

	if err == nil {
		go n.watchMiss(nlSock)
	} else {
		logrus.Errorf("failed to subscribe to neighbor group netlink messages for overlay network %s in sbox %s: %v",
			n.id, sbox.Key(), err)
	}

	return nil
}

func (n *network) watchMiss(nlSock *nl.NetlinkSocket) {
	for {
		msgs, err := nlSock.Receive()
		if err != nil {
			logrus.Errorf("Failed to receive from netlink: %v ", err)
			continue
		}

		for _, msg := range msgs {
			if msg.Header.Type != syscall.RTM_GETNEIGH && msg.Header.Type != syscall.RTM_NEWNEIGH {
				continue
			}

			neigh, err := netlink.NeighDeserialize(msg.Data)
			if err != nil {
				logrus.Errorf("Failed to deserialize netlink ndmsg: %v", err)
				continue
			}

			var (
				ip             net.IP
				mac            net.HardwareAddr
				l2Miss, l3Miss bool
			)
			if neigh.IP.To4() != nil {
				ip = neigh.IP
				l3Miss = true
			} else if neigh.HardwareAddr != nil {
				mac = []byte(neigh.HardwareAddr)
				ip = net.IP(mac[2:])
				l2Miss = true
			} else {
				continue
			}

			// Not any of the network's subnets. Ignore.
			if !n.contains(ip) {
				continue
			}

			logrus.Debugf("miss notification: dest IP %v, dest MAC %v", ip, mac)

			if neigh.State&(netlink.NUD_STALE|netlink.NUD_INCOMPLETE) == 0 {
				continue
			}

			if !n.driver.isSerfAlive() {
				continue
			}

			mac, IPmask, vtep, err := n.driver.resolvePeer(n.id, ip)
			if err != nil {
				logrus.Errorf("could not resolve peer %q: %v", ip, err)
				continue
			}

			if err := n.driver.peerAdd(n.id, "dummy", ip, IPmask, mac, vtep, true, l2Miss, l3Miss); err != nil {
				logrus.Errorf("could not add neighbor entry for missed peer %q: %v", ip, err)
			}
		}
	}
}

func (d *driver) addNetwork(n *network) {
	d.Lock()
	d.networks[n.id] = n
	d.Unlock()
}

func (d *driver) deleteNetwork(nid string) {
	d.Lock()
	delete(d.networks, nid)
	d.Unlock()
}

func (d *driver) network(nid string) *network {
	d.Lock()
	n, ok := d.networks[nid]
	d.Unlock()
	if !ok {
		n = d.getNetworkFromStore(nid)
		if n != nil {
			n.driver = d
			n.endpoints = endpointTable{}
			n.once = &sync.Once{}
			d.Lock()
			d.networks[nid] = n
			d.Unlock()
		}
	}

	return n
}

func (d *driver) getNetworkFromStore(nid string) *network {
	if d.store == nil {
		return nil
	}

	n := &network{id: nid}
	if err := d.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
		return nil
	}

	return n
}

func (n *network) sandbox() osl.Sandbox {
	n.Lock()
	defer n.Unlock()

	return n.sbox
}

func (n *network) setSandbox(sbox osl.Sandbox) {
	n.Lock()
	n.sbox = sbox
	n.Unlock()
}

func (n *network) vxlanID(s *subnet) uint32 {
	n.Lock()
	defer n.Unlock()

	return s.vni
}

func (n *network) setVxlanID(s *subnet, vni uint32) {
	n.Lock()
	s.vni = vni
	n.Unlock()
}

func (n *network) Key() []string {
	return []string{"overlay", "network", n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{"overlay", "network"}
}

func (n *network) Value() []byte {
	m := map[string]interface{}{}

	netJSON := []*subnetJSON{}

	for _, s := range n.subnets {
		sj := &subnetJSON{
			SubnetIP: s.subnetIP.String(),
			GwIP:     s.gwIP.String(),
			Vni:      s.vni,
		}
		netJSON = append(netJSON, sj)
	}

	b, err := json.Marshal(netJSON)
	if err != nil {
		return []byte{}
	}

	m["secure"] = n.secure
	m["subnets"] = netJSON
	m["mtu"] = n.mtu
	b, err = json.Marshal(m)
	if err != nil {
		return []byte{}
	}

	return b
}

func (n *network) Index() uint64 {
	return n.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.dbIndex = index
	n.dbExists = true
}

func (n *network) Exists() bool {
	return n.dbExists
}

func (n *network) Skip() bool {
	return false
}

func (n *network) SetValue(value []byte) error {
	var (
		m       map[string]interface{}
		newNet  bool
		isMap   = true
		netJSON = []*subnetJSON{}
	)

	if err := json.Unmarshal(value, &m); err != nil {
		err := json.Unmarshal(value, &netJSON)
		if err != nil {
			return err
		}
		isMap = false
	}

	if len(n.subnets) == 0 {
		newNet = true
	}

	if isMap {
		if val, ok := m["secure"]; ok {
			n.secure = val.(bool)
		}
		if val, ok := m["mtu"]; ok {
			n.mtu = int(val.(float64))
		}
		bytes, err := json.Marshal(m["subnets"])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bytes, &netJSON); err != nil {
			return err
		}
	}

	for _, sj := range netJSON {
		subnetIPstr := sj.SubnetIP
		gwIPstr := sj.GwIP
		vni := sj.Vni

		subnetIP, _ := types.ParseCIDR(subnetIPstr)
		gwIP, _ := types.ParseCIDR(gwIPstr)

		if newNet {
			s := &subnet{
				subnetIP: subnetIP,
				gwIP:     gwIP,
				vni:      vni,
				once:     &sync.Once{},
			}
			n.subnets = append(n.subnets, s)
		} else {
			sNet := n.getMatchingSubnet(subnetIP)
			if sNet != nil {
				sNet.vni = vni
			}
		}
	}
	return nil
}

func (n *network) DataScope() string {
	return datastore.GlobalScope
}

func (n *network) writeToStore() error {
	if n.driver.store == nil {
		return nil
	}

	return n.driver.store.PutObjectAtomic(n)
}

func (n *network) releaseVxlanID() ([]uint32, error) {
	if len(n.subnets) == 0 {
		return nil, nil
	}

	if n.driver.store != nil {
		if err := n.driver.store.DeleteObjectAtomic(n); err != nil {
			if err == datastore.ErrKeyModified || err == datastore.ErrKeyNotFound {
				// In both the above cases we can safely assume that the key has been removed by some other
				// instance and so simply get out of here
				return nil, nil
			}

			return nil, fmt.Errorf("failed to delete network to vxlan id map: %v", err)
		}
	}
	var vnis []uint32
	for _, s := range n.subnets {
		if n.driver.vxlanIdm != nil {
			vni := n.vxlanID(s)
			vnis = append(vnis, vni)
			// 通过指定driver指定的Idm来释放vni
			n.driver.vxlanIdm.Release(uint64(vni))
		}

		// 为每个子网的vxlan ID 设置为0
		n.setVxlanID(s, 0)
	}

	// 返回所有被释放到的vni
	return vnis, nil
}

func (n *network) obtainVxlanID(s *subnet) error {
	//return if the subnet already has a vxlan id assigned
	if s.vni != 0 {
		return nil
	}

	if n.driver.store == nil {
		return fmt.Errorf("no valid vxlan id and no datastore configured, cannot obtain vxlan id")
	}

	for {
		if err := n.driver.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
			return fmt.Errorf("getting network %q from datastore failed %v", n.id, err)
		}

		if s.vni == 0 {
			vxlanID, err := n.driver.vxlanIdm.GetID()
			if err != nil {
				return fmt.Errorf("failed to allocate vxlan id: %v", err)
			}

			n.setVxlanID(s, uint32(vxlanID))
			if err := n.writeToStore(); err != nil {
				n.driver.vxlanIdm.Release(uint64(n.vxlanID(s)))
				n.setVxlanID(s, 0)
				if err == datastore.ErrKeyModified {
					continue
				}
				return fmt.Errorf("network %q failed to update data store: %v", n.id, err)
			}
			return nil
		}
		return nil
	}
}

// contains return true if the passed ip belongs to one the network's
// subnets
func (n *network) contains(ip net.IP) bool {
	for _, s := range n.subnets {
		if s.subnetIP.Contains(ip) {
			return true
		}
	}

	return false
}

// getSubnetforIP returns the subnet to which the given IP belongs
func (n *network) getSubnetforIP(ip *net.IPNet) *subnet {
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.Contains(ip.IP) {
			return s
		}
	}
	return nil
}

// getMatchingSubnet return the network's subnet that matches the input
func (n *network) getMatchingSubnet(ip *net.IPNet) *subnet {
	if ip == nil {
		return nil
	}
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.IP.Equal(ip.IP) {
			return s
		}
	}
	return nil
}
