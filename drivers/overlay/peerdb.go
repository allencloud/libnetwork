package overlay

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
)

const ovPeerTable = "overlay_peer_table"

// peerKey 最终会作为单个 network 中 peerMap 的key值
type peerKey struct {
	peerIP  net.IP
	peerMac net.HardwareAddr
}

// peerDb首先通过network进行分类，然后通过peerKey进行分类
// 分类完后，每一个value就是peerEntry
type peerEntry struct {
	eid        string     // endpoint ID
	vtep       net.IP     // VXLAN Tunneling End Point 的IP地址
	peerIPMask net.IPMask //
	inSandbox  bool       //
	isLocal    bool       //
}

// 单个network用来存储peer信息的集合
type peerMap struct {
	mp map[string]peerEntry
	sync.Mutex
}

// peerNetworkMap相当于首先通过network ID来区分的peer信息
type peerNetworkMap struct {
	mp map[string]*peerMap
	sync.Mutex
}

// String 方法主要用于实现key的构建
func (pKey peerKey) String() string {
	return fmt.Sprintf("%s %s", pKey.peerIP, pKey.peerMac)
}

func (pKey *peerKey) Scan(state fmt.ScanState, verb rune) error {
	ipB, err := state.Token(true, nil)
	if err != nil {
		return err
	}

	pKey.peerIP = net.ParseIP(string(ipB))

	macB, err := state.Token(true, nil)
	if err != nil {
		return err
	}

	pKey.peerMac, err = net.ParseMAC(string(macB))
	if err != nil {
		return err
	}

	return nil
}

var peerDbWg sync.WaitGroup

func (d *driver) peerDbWalk(f func(string, *peerKey, *peerEntry) bool) error {
	d.peerDb.Lock()
	// 搜集出所有的network ID
	nids := []string{}
	for nid := range d.peerDb.mp {
		nids = append(nids, nid)
	}
	d.peerDb.Unlock()

	// 针对每个network, 进行相应的peerDbNetworkWalk
	for _, nid := range nids {
		d.peerDbNetworkWalk(nid, func(pKey *peerKey, pEntry *peerEntry) bool {
			return f(nid, pKey, pEntry)
		})
	}
	return nil
}

// peerDbNetworkWalk 首先通过nid找到peerDb中与network ID相对应的组;
// 随后将组内每一个endpoint所代表的peer点，通过传入的f函数做相应的操作
func (d *driver) peerDbNetworkWalk(nid string, f func(*peerKey, *peerEntry) bool) error {
	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	d.peerDb.Unlock()

	if !ok {
		return nil
	}

	// mp用于复刻peerDb中有关于输入network的peer组
	mp := map[string]peerEntry{}

	pMap.Lock()
	for pKeyStr, pEntry := range pMap.mp {
		mp[pKeyStr] = pEntry
	}
	pMap.Unlock()
	// 复刻完成

	for pKeyStr, pEntry := range mp {
		var pKey peerKey
		if _, err := fmt.Sscan(pKeyStr, &pKey); err != nil {
			logrus.Warnf("Peer key scan on network %s failed: %v", nid, err)
		}
		// 针对peerDb中已经单个network内的endpoint信息，每一个进行执行f函数
		if f(&pKey, &pEntry) {
			return nil
		}
	}

	return nil
}

// peerDbSearch 通过network ID找到相应的network组，再在network中找到相应peer IP所在的那个endpoint的值
// 返回相应endpoint的IP地址，掩码以及MAC地址
func (d *driver) peerDbSearch(nid string, peerIP net.IP) (net.HardwareAddr, net.IPMask, net.IP, error) {
	var (
		peerMac    net.HardwareAddr
		vtep       net.IP
		peerIPMask net.IPMask
		found      bool
	)

	// 描述一个函数，这个函数用于比对peerIP的值，
	// 最终返回该 peer endpoint的MAC地址，IP掩码以及IP地址
	f := func(pKey *peerKey, pEntry *peerEntry) bool {
		if pKey.peerIP.Equal(peerIP) { // 这里的peerIP是用户输入的peerIP信息
			peerMac = pKey.peerMac
			peerIPMask = pEntry.peerIPMask
			vtep = pEntry.vtep
			found = true
			return found
		}

		return found
	}

	err := d.peerDbNetworkWalk(nid, f)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("peerdb search for peer ip %q failed: %v", peerIP, err)
	}

	if !found {
		return nil, nil, nil, fmt.Errorf("peer ip %q not found in peerdb", peerIP)
	}

	return peerMac, peerIPMask, vtep, nil
}

// peerDbAdd主要实现将一个endpoint的信息加入peerDb中
// peerDb中的信息都是通过network来区分的
func (d *driver) peerDbAdd(nid, // endpoint 所在的network ID
	eid string, // endpoint 自身的endpoint ID
	peerIP net.IP, // endpoint自身的IP地址, 用于构建key的前半部分
	peerIPMask net.IPMask, // endpoint自身所在的掩码
	peerMac net.HardwareAddr, // endpoint自身的mac地址，用户构建key的后半部分，最终是"ip mac"
	vtep net.IP, // VTEP的IP地址
	isLocal bool, // 是否用于本地
) {

	peerDbWg.Wait()

	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		// 如果现有的network不存在于peerDb中
		d.peerDb.mp[nid] = &peerMap{
			mp: make(map[string]peerEntry),
		}

		// pMap是peerDb中单个network中的所有peer集合
		pMap = d.peerDb.mp[nid]
	}
	d.peerDb.Unlock()

	pKey := peerKey{
		peerIP:  peerIP,
		peerMac: peerMac,
	}

	pEntry := peerEntry{
		eid:        eid,        // endpoint ID
		vtep:       vtep,       // VTEP
		peerIPMask: peerIPMask, //
		isLocal:    isLocal,    //
	}

	pMap.Lock()
	// pKey.String()= "ip mac"
	pMap.mp[pKey.String()] = pEntry
	pMap.Unlock()
}

// peerDbDelete主要实现将一个endpoint的信息从peerDb中删除
// peerDb中的信息都是通过network来区分的
func (d *driver) peerDbDelete(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP) peerEntry {
	peerDbWg.Wait()

	d.peerDb.Lock()
	// 通过endpoint所在的network，找到改endpoint在peerDb中所在的network组
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.Unlock()
		return peerEntry{}
	}
	d.peerDb.Unlock()

	// 构建peerKey
	pKey := peerKey{
		peerIP:  peerIP,
		peerMac: peerMac,
	}

	pMap.Lock()

	pEntry, ok := pMap.mp[pKey.String()]
	if ok {
		// Mismatched endpoint ID(possibly outdated). Do not
		// delete peerdb
		if pEntry.eid != eid {
			pMap.Unlock()
			return pEntry
		}
	}

	// 将相应的peerKey所代表的peer信息删除
	delete(pMap.mp, pKey.String())
	pMap.Unlock()

	return pEntry
}

func (d *driver) peerDbUpdateSandbox(nid string) {
	d.peerDb.Lock()
	pMap, ok := d.peerDb.mp[nid]
	if !ok {
		d.peerDb.Unlock()
		return
	}
	d.peerDb.Unlock()

	peerDbWg.Add(1)

	var peerOps []func()
	pMap.Lock()
	for pKeyStr, pEntry := range pMap.mp {
		var pKey peerKey
		if _, err := fmt.Sscan(pKeyStr, &pKey); err != nil {
			fmt.Printf("peer key scan failed: %v", err)
		}

		if pEntry.isLocal {
			continue
		}

		// Go captures variables by reference. The pEntry could be
		// pointing to the same memory location for every iteration. Make
		// a copy of pEntry before capturing it in the following closure.
		entry := pEntry
		op := func() {
			if err := d.peerAdd(nid, entry.eid, pKey.peerIP, entry.peerIPMask,
				pKey.peerMac, entry.vtep,
				false, false, false); err != nil {
				fmt.Printf("peerdbupdate in sandbox failed for ip %s and mac %s: %v",
					pKey.peerIP, pKey.peerMac, err)
			}
		}

		peerOps = append(peerOps, op)
	}
	pMap.Unlock()

	for _, op := range peerOps {
		op()
	}

	peerDbWg.Done()
}

func (d *driver) peerAdd(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP, updateDb, l2Miss, l3Miss bool) error {

	// 查看输入的ID是否有存在为空的
	if err := validateID(nid, eid); err != nil {
		return err
	}

	if updateDb {
		d.peerDbAdd(nid, eid, peerIP, peerIPMask, peerMac, vtep, false)
	}

	// 找到对应的具体network对象
	n := d.network(nid)
	if n == nil {
		return nil
	}

	// 找到network具体对应的Sandbox对象
	sbox := n.sandbox()
	if sbox == nil {
		return nil
	}

	// 通过输入的peer IP和掩码信息，构建IP网络地址
	IP := &net.IPNet{
		IP:   peerIP,
		Mask: peerIPMask,
	}

	// 通过输入的IP网络地址，找到在network中存在的子网subnet信息
	s := n.getSubnetforIP(IP)
	if s == nil {
		return fmt.Errorf("couldn't find the subnet %q in network %q", IP.String(), n.id)
	}

	// 找到network想对应的VxLan ID
	if err := n.obtainVxlanID(s); err != nil {
		return fmt.Errorf("couldn't get vxlan id for %q: %v", s.subnetIP.String(), err)
	}

	// 将子网subnet加入到network所在的Sandbox中
	if err := n.joinSubnetSandbox(s, false); err != nil {
		return fmt.Errorf("subnet sandbox join failed for %q: %v", s.subnetIP.String(), err)
	}

	// 查看是否需要使用加密
	if err := d.checkEncryption(nid, vtep, n.vxlanID(s), false, true); err != nil {
		logrus.Warn(err)
	}

	// Add neighbor entry for the peer IP
	// 将peer节点的IP地址，MAC地址加入到所属Sandbox的neighbour列表中
	if err := sbox.AddNeighbor(peerIP, peerMac, l3Miss, sbox.NeighborOptions().LinkName(s.vxlanName)); err != nil {
		return fmt.Errorf("could not add neighbor entry into the sandbox: %v", err)
	}

	// Add fdb entry to the bridge for the peer mac
	// 将VTEP的IP地址，MAC地址加入到所属Sandbox的neighour列表中
	if err := sbox.AddNeighbor(vtep, peerMac, l2Miss, sbox.NeighborOptions().LinkName(s.vxlanName),
		sbox.NeighborOptions().Family(syscall.AF_BRIDGE)); err != nil {
		return fmt.Errorf("could not add fdb entry into the sandbox: %v", err)
	}

	return nil
}

func (d *driver) peerDelete(nid, eid string, peerIP net.IP, peerIPMask net.IPMask,
	peerMac net.HardwareAddr, vtep net.IP, updateDb bool) error {

	if err := validateID(nid, eid); err != nil {
		return err
	}

	var pEntry peerEntry
	if updateDb {
		pEntry = d.peerDbDelete(nid, eid, peerIP, peerIPMask, peerMac, vtep)
	}

	n := d.network(nid)
	if n == nil {
		return nil
	}

	sbox := n.sandbox()
	if sbox == nil {
		return nil
	}

	// Delete fdb entry to the bridge for the peer mac only if the
	// entry existed in local peerdb. If it is a stale delete
	// request, still call DeleteNeighbor but only to cleanup any
	// leftover sandbox neighbor cache and not actually delete the
	// kernel state.
	if (eid == pEntry.eid && vtep.Equal(pEntry.vtep)) ||
		(eid != pEntry.eid && !vtep.Equal(pEntry.vtep)) {
		if err := sbox.DeleteNeighbor(vtep, peerMac,
			eid == pEntry.eid && vtep.Equal(pEntry.vtep)); err != nil {
			return fmt.Errorf("could not delete fdb entry into the sandbox: %v", err)
		}
	}

	// Delete neighbor entry for the peer IP
	if eid == pEntry.eid {
		if err := sbox.DeleteNeighbor(peerIP, peerMac, true); err != nil {
			return fmt.Errorf("could not delete neighbor entry into the sandbox: %v", err)
		}
	}

	if err := d.checkEncryption(nid, vtep, 0, false, false); err != nil {
		logrus.Warn(err)
	}

	return nil
}

func (d *driver) pushLocalDb() {
	d.peerDbWalk(func(nid string, pKey *peerKey, pEntry *peerEntry) bool {
		if pEntry.isLocal {
			d.pushLocalEndpointEvent("join", nid, pEntry.eid)
		}
		return false
	})
}

func (d *driver) peerDBUpdateSelf() {
	d.peerDbWalk(func(nid string, pkey *peerKey, pEntry *peerEntry) bool {
		if pEntry.isLocal {
			pEntry.vtep = net.ParseIP(d.advertiseAddress)
		}
		return false
	})
}
