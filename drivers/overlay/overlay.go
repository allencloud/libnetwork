package overlay

//go:generate protoc -I.:../../Godeps/_workspace/src/github.com/gogo/protobuf  --gogo_out=import_path=github.com/docker/libnetwork/drivers/overlay,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto:. overlay.proto

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/idm"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/types"
	"github.com/hashicorp/serf/serf"
)

const (
	networkType  = "overlay"     // 网络类型为overlay
	vethPrefix   = "veth"        //
	vethLen      = 7             //
	vxlanIDStart = 256           //
	vxlanIDEnd   = (1 << 24) - 1 //
	vxlanPort    = 4789          // 缺省情况下，VxLan报文的目的的UDP端口号为4789
	vxlanEncap   = 50            // 使用MAC in UDP的方法进行封装，共50字节的封装报文头
	secureOption = "encrypted"
)

var initVxlanIdm = make(chan (bool), 1)

type driver struct {
	eventCh          chan serf.Event
	notifyCh         chan ovNotify
	exitCh           chan chan struct{}
	bindAddress      string
	advertiseAddress string
	neighIP          string
	config           map[string]interface{}
	peerDb           peerNetworkMap      // 每个overlay驱动中，需要存在用于peer传播的信息，首先通过network分类，然后再通过
	secMap           *encrMap            // secMap 主要用于记录哪些节点需要实现使用ipSec进行加密
	serfInstance     *serf.Serf          // overlay的driver，拥有一个serf实例，用户维护所有的成员信息
	networks         networkTable        // 特定driver会管理一个列表，其中所有的network都是该driver创建出来的
	store            datastore.DataStore // overlay 驱动会在本地存储中存储所有的endpoint信息，需要本地存储地址
	localStore       datastore.DataStore // overlay 驱动会在远程存储中存储部分信息，需要远程存储地址
	vxlanIdm         *idm.Idm            // overlay 驱动的需要管理一个ID管理器，该ID管理器会用来实现vxlan ID的管理
	once             sync.Once           //
	joinOnce         sync.Once           //
	localJoinOnce    sync.Once           //
	keys             []*key
	sync.Mutex
}

// Init registers a new instance of overlay driver
// 初始化Overlay的Driver
func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
	// 说明overlay的视角在初始化的时候就设为全局global，合情合理
	c := driverapi.Capability{
		DataScope: datastore.GlobalScope,
	}
	d := &driver{
		networks: networkTable{},
		// 创建一个peerDb
		peerDb: peerNetworkMap{
			mp: map[string]*peerMap{},
		},
		secMap: &encrMap{nodes: map[string][]*spi{}},
		config: config,
	}

	// overlay 驱动需要完成数据的全局存储，d.store主要完成远程存储地址的配置
	if data, ok := config[netlabel.GlobalKVClient]; ok {
		var err error
		dsc, ok := data.(discoverapi.DatastoreConfigData)
		if !ok {
			return types.InternalErrorf("incorrect data in datastore configuration: %v", data)
		}
		d.store, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			return types.InternalErrorf("failed to initialize data store: %v", err)
		}
	}

	// overlay 驱动需要完成数据的本地存储，d.store主要完成本地存储地址的配置
	if data, ok := config[netlabel.LocalKVClient]; ok {
		var err error
		dsc, ok := data.(discoverapi.DatastoreConfigData)
		if !ok {
			return types.InternalErrorf("incorrect data in datastore configuration: %v", data)
		}
		d.localStore, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			return types.InternalErrorf("failed to initialize local data store: %v", err)
		}
	}

	// 启动过程中overlay驱动需要重新加载所有应该归该驱动管理的endpoint
	if err := d.restoreEndpoints(); err != nil {
		logrus.Warnf("Failure during overlay endpoints restore: %v", err)
	}

	// If an error happened when the network join the sandbox during the endpoints restore
	// we should reset it now along with the once variable, so that subsequent endpoint joins
	// outside of the restore path can potentially fix the network join and succeed.
	for nid, n := range d.networks {
		if n.initErr != nil {
			logrus.Infof("resetting init error and once variable for network %s after unsuccessful endpoint restore: %v", nid, n.initErr)
			n.initErr = nil
			n.once = &sync.Once{}
		}
	}

	return dc.RegisterDriver(networkType, d, c)
}

// Endpoints are stored in the local store. Restore them and reconstruct the overlay sandbox
func (d *driver) restoreEndpoints() error {
	if d.localStore == nil {
		logrus.Warn("Cannot restore overlay endpoints because local datastore is missing")
		return nil
	}
	// 从本地存储中获取相应的overlay endpoint
	kvol, err := d.localStore.List(datastore.Key(overlayEndpointPrefix), &endpoint{})
	if err != nil && err != datastore.ErrKeyNotFound {
		return fmt.Errorf("failed to read overlay endpoint from store: %v", err)
	}

	if err == datastore.ErrKeyNotFound {
		return nil
	}
	for _, kvo := range kvol {
		ep := kvo.(*endpoint)
		// 每个driver的networks属性中存储所有的overlay网络
		// 通过network id，找到endpoint所在的网络
		n := d.network(ep.nid)
		if n == nil {
			logrus.Debugf("Network (%s) not found for restored endpoint (%s)", ep.nid[0:7], ep.id[0:7])
			logrus.Debugf("Deleting stale overlay endpoint (%s) from store", ep.id[0:7])
			// 如果没有找到相应的network，那就删除这个没有network归属的endpoint
			if err := d.deleteEndpointFromStore(ep); err != nil {
				logrus.Debugf("Failed to delete stale overlay endpoint (%s) from store", ep.id[0:7])
			}
			continue
		}
		// 在endpoing应该归属的network中添加此endpoint
		n.addEndpoint(ep)

		// 需要endpoint的网络地址，获取这个endpoint所在network的子网信息
		// 不同的enpdpoint有可能存在于不同的subnet子网中
		s := n.getSubnetforIP(ep.addr)
		if s == nil {
			return fmt.Errorf("could not find subnet for endpoint %s", ep.id)
		}

		// 要让overlay网络重新创建Sandbox
		if err := n.joinSandbox(true); err != nil {
			return fmt.Errorf("restore network sandbox failed: %v", err)
		}

		// 通过endpoint的子网地址，找到相应的子网设备，
		// 把相应的子网Sandbox完成初始化工作，比如创建网络接口，配置路由规则等
		if err := n.joinSubnetSandbox(s, true); err != nil {
			return fmt.Errorf("restore subnet sandbox failed for %q: %v", s.subnetIP.String(), err)
		}

		Ifaces := make(map[string][]osl.IfaceOption)
		vethIfaceOption := make([]osl.IfaceOption, 1)
		vethIfaceOption = append(vethIfaceOption, n.sbox.InterfaceOptions().Master(s.brName))
		Ifaces[fmt.Sprintf("%s+%s", "veth", "veth")] = vethIfaceOption

		err := n.sbox.Restore(Ifaces, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to restore overlay sandbox: %v", err)
		}

		// 增加network中endpoint的存储数量
		n.incEndpointCount()
		// restore的过程中，每有一个endpoint，都将endpoint用于通信的信息存入peerDb中
		d.peerDbAdd(ep.nid, ep.id, ep.addr.IP, ep.addr.Mask, ep.mac, net.ParseIP(d.advertiseAddress), true)
	}
	return nil
}

// Fini cleans up the driver resources
func Fini(drv driverapi.Driver) {
	d := drv.(*driver)

	if d.exitCh != nil {
		waitCh := make(chan struct{})

		d.exitCh <- waitCh

		<-waitCh
	}
}

func (d *driver) configure() error {
	if d.store == nil {
		return nil
	}

	if d.vxlanIdm == nil {
		return d.initializeVxlanIdm()
	}

	return nil
}

func (d *driver) initializeVxlanIdm() error {
	var err error

	initVxlanIdm <- true
	defer func() { <-initVxlanIdm }()

	if d.vxlanIdm != nil {
		return nil
	}

	d.vxlanIdm, err = idm.New(d.store, "vxlan-id", vxlanIDStart, vxlanIDEnd)
	if err != nil {
		return fmt.Errorf("failed to initialize vxlan id manager: %v", err)
	}

	return nil
}

func (d *driver) Type() string {
	return networkType
}

func (d *driver) IsBuiltIn() bool {
	return true
}

func validateSelf(node string) error {
	advIP := net.ParseIP(node)
	if advIP == nil {
		return fmt.Errorf("invalid self address (%s)", node)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("Unable to get interface addresses %v", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.Equal(advIP) {
			return nil
		}
	}
	return fmt.Errorf("Multi-Host overlay networking requires cluster-advertise(%s) to be configured with a local ip-address that is reachable within the cluster", advIP.String())
}

func (d *driver) nodeJoin(advertiseAddress, bindAddress string, self bool) {
	if self && !d.isSerfAlive() {
		d.Lock()
		d.advertiseAddress = advertiseAddress
		d.bindAddress = bindAddress
		d.Unlock()

		// If containers are already running on this network update the
		// advertiseaddress in the peerDB
		d.localJoinOnce.Do(func() {
			d.peerDBUpdateSelf()
		})

		// If there is no cluster store there is no need to start serf.
		if d.store != nil {
			if err := validateSelf(advertiseAddress); err != nil {
				logrus.Warnf("%s", err.Error())
			}
			err := d.serfInit()
			if err != nil {
				logrus.Errorf("initializing serf instance failed: %v", err)
				d.Lock()
				d.advertiseAddress = ""
				d.bindAddress = ""
				d.Unlock()
				return
			}
		}
	}

	d.Lock()
	if !self {
		d.neighIP = advertiseAddress
	}
	neighIP := d.neighIP
	d.Unlock()

	if d.serfInstance != nil && neighIP != "" {
		var err error
		d.joinOnce.Do(func() {
			err = d.serfJoin(neighIP)
			if err == nil {
				d.pushLocalDb()
			}
		})
		if err != nil {
			logrus.Errorf("joining serf neighbor %s failed: %v", advertiseAddress, err)
			d.Lock()
			d.joinOnce = sync.Once{}
			d.Unlock()
			return
		}
	}
}

func (d *driver) pushLocalEndpointEvent(action, nid, eid string) {
	n := d.network(nid)
	if n == nil {
		logrus.Debugf("Error pushing local endpoint event for network %s", nid)
		return
	}
	ep := n.endpoint(eid)
	if ep == nil {
		logrus.Debugf("Error pushing local endpoint event for ep %s / %s", nid, eid)
		return
	}

	if !d.isSerfAlive() {
		return
	}
	d.notifyCh <- ovNotify{
		action: "join",
		nw:     n,
		ep:     ep,
	}
}

// DiscoverNew is a notification for a new discovery event, such as a new node joining a cluster
func (d *driver) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	var err error
	switch dType {
	case discoverapi.NodeDiscovery:
		nodeData, ok := data.(discoverapi.NodeDiscoveryData)
		if !ok || nodeData.Address == "" {
			return fmt.Errorf("invalid discovery data")
		}
		d.nodeJoin(nodeData.Address, nodeData.BindAddress, nodeData.Self)
	case discoverapi.DatastoreConfig:
		if d.store != nil {
			return types.ForbiddenErrorf("cannot accept datastore configuration: Overlay driver has a datastore configured already")
		}
		dsc, ok := data.(discoverapi.DatastoreConfigData)
		if !ok {
			return types.InternalErrorf("incorrect data in datastore configuration: %v", data)
		}
		d.store, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			return types.InternalErrorf("failed to initialize data store: %v", err)
		}
	case discoverapi.EncryptionKeysConfig:
		encrData, ok := data.(discoverapi.DriverEncryptionConfig)
		if !ok {
			return fmt.Errorf("invalid encryption key notification data")
		}
		keys := make([]*key, 0, len(encrData.Keys))
		for i := 0; i < len(encrData.Keys); i++ {
			k := &key{
				value: encrData.Keys[i],
				tag:   uint32(encrData.Tags[i]),
			}
			keys = append(keys, k)
		}
		if err := d.setKeys(keys); err != nil {
			logrus.Warn(err)
		}
	case discoverapi.EncryptionKeysUpdate:
		var newKey, delKey, priKey *key
		encrData, ok := data.(discoverapi.DriverEncryptionUpdate)
		if !ok {
			return fmt.Errorf("invalid encryption key notification data")
		}
		if encrData.Key != nil {
			newKey = &key{
				value: encrData.Key,
				tag:   uint32(encrData.Tag),
			}
		}
		if encrData.Primary != nil {
			priKey = &key{
				value: encrData.Primary,
				tag:   uint32(encrData.PrimaryTag),
			}
		}
		if encrData.Prune != nil {
			delKey = &key{
				value: encrData.Prune,
				tag:   uint32(encrData.PruneTag),
			}
		}
		if err := d.updateKeys(newKey, priKey, delKey); err != nil {
			logrus.Warn(err)
		}
	default:
	}
	return nil
}

// DiscoverDelete is a notification for a discovery delete event, such as a node leaving a cluster
func (d *driver) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}
