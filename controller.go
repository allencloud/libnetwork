/*
Package libnetwork provides the basic functionality and extension points to
create network namespaces and allocate interfaces for containers to use.

	networkType := "bridge"

	// Create a new controller instance
	driverOptions := options.Generic{}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = driverOptions
	controller, err := libnetwork.New(config.OptionDriverConfig(networkType, genericOption))
	if err != nil {
		return
	}

	// Create a network for containers to join.
	// NewNetwork accepts Variadic optional arguments that libnetwork and Drivers can make use of
	network, err := controller.NewNetwork(networkType, "network1", "")
	if err != nil {
		return
	}

	// For each new container: allocate IP and interfaces. The returned network
	// settings will be used for container infos (inspect and such), as well as
	// iptables rules for port publishing. This info is contained or accessible
	// from the returned endpoint.
	ep, err := network.CreateEndpoint("Endpoint1")
	if err != nil {
		return
	}

	// Create the sandbox for the container.
	// NewSandbox accepts Variadic optional arguments which libnetwork can use.
	sbx, err := controller.NewSandbox("container1",
		libnetwork.OptionHostname("test"),
		libnetwork.OptionDomainname("docker.io"))

	// A sandbox can join the endpoint via the join api.
	err = ep.Join(sbx)
	if err != nil {
		return
	}
*/
package libnetwork

import (
	"container/heap"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/discovery"
	"github.com/docker/docker/pkg/locker"
	"github.com/docker/docker/pkg/plugingetter"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/libnetwork/cluster"
	"github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/drvregistry"
	"github.com/docker/libnetwork/hostdiscovery"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/types"
)

// NetworkController provides the interface for controller instance which manages
// networks.
type NetworkController interface {
	// ID provides a unique identity for the controller
	ID() string

	// BuiltinDrivers returns list of builtin drivers
	BuiltinDrivers() []string

	// BuiltinIPAMDrivers returns list of builtin ipam drivers
	BuiltinIPAMDrivers() []string

	// Config method returns the bootup configuration for the controller
	Config() config.Config

	// Create a new network. The options parameter carries network specific options.
	NewNetwork(networkType, name string, id string, options ...NetworkOption) (Network, error)

	// Networks returns the list of Network(s) managed by this controller.
	Networks() []Network

	// WalkNetworks uses the provided function to walk the Network(s) managed by this controller.
	WalkNetworks(walker NetworkWalker)

	// NetworkByName returns the Network which has the passed name. If not found, the error ErrNoSuchNetwork is returned.
	NetworkByName(name string) (Network, error)

	// NetworkByID returns the Network which has the passed id. If not found, the error ErrNoSuchNetwork is returned.
	NetworkByID(id string) (Network, error)

	// NewSandbox creates a new network sandbox for the passed container id
	NewSandbox(containerID string, options ...SandboxOption) (Sandbox, error)

	// Sandboxes returns the list of Sandbox(s) managed by this controller.
	Sandboxes() []Sandbox

	// WalkSandboxes uses the provided function to walk the Sandbox(s) managed by this controller.
	WalkSandboxes(walker SandboxWalker)

	// SandboxByID returns the Sandbox which has the passed id. If not found, a types.NotFoundError is returned.
	SandboxByID(id string) (Sandbox, error)

	// SandboxDestroy destroys a sandbox given a container ID
	SandboxDestroy(id string) error

	// Stop network controller
	Stop()

	// ReloadCondfiguration updates the controller configuration
	ReloadConfiguration(cfgOptions ...config.Option) error

	// SetClusterProvider sets cluster provider
	SetClusterProvider(provider cluster.Provider)

	// Wait for agent initialization complete in libnetwork controller
	AgentInitWait()

	// SetKeys configures the encryption key for gossip and overlay data path
	SetKeys(keys []*types.EncryptionKey) error
}

// NetworkWalker is a client provided function which will be used to walk the Networks.
// When the function returns true, the walk will stop.
type NetworkWalker func(nw Network) bool

// SandboxWalker is a client provided function which will be used to walk the Sandboxes.
// When the function returns true, the walk will stop.
type SandboxWalker func(sb Sandbox) bool

type sandboxTable map[string]*sandbox

type controller struct {
	id                     string
	drvRegistry            *drvregistry.DrvRegistry    // 用于存储所有的driver，包括每一个driver的配置信息
	sandboxes              sandboxTable                // 存放在内存的中的Sandbox列表
	cfg                    *config.Config              // 由docker daemon传入的libnetwork配置
	stores                 []datastore.DataStore       // 创建出的网络信息存储，比如local的boltdb，global的etcd等
	discovery              hostdiscovery.HostDiscovery // 用于接收节点发现的事件
	extKeyListener         net.Listener                // 一个listener，主要监听一个socket，以保障获取外部的网络密钥输入
	watchCh                chan *endpoint              // 监听是否有新的endpoint创建
	unWatchCh              chan *endpoint              // 监听是否有endpoint需要被删除
	svcRecords             map[string]svcInfo          // 一个controller中，收集的所有的service记录
	nmap                   map[string]*netWatch        //
	serviceBindings        map[serviceKey]*service     //
	defOsSbox              osl.Sandbox                 //
	ingressSandbox         *sandbox                    // 每一个controller都有一个指向ingress snadbox的指针, 如果不启动swarm mode的话，指针应该为空
	sboxOnce               sync.Once                   //
	agent                  *agent                      // 每一个controller，都有一个重要的agent对象，负责gossip以及store同步的事
	networkLocker          *locker.Locker              //
	agentInitDone          chan struct{}               // 一个管道，标志着agent的初始化工作是否完成
	keys                   []*types.EncryptionKey      //
	clusterConfigAvailable bool                        //
	sync.Mutex
}

type initializer struct {
	fn    drvregistry.InitFunc
	ntype string
}

// New creates a new instance of network controller.
func New(cfgOptions ...config.Option) (NetworkController, error) {
	c := &controller{
		id:              stringid.GenerateRandomID(),
		cfg:             config.ParseConfigOptions(cfgOptions...), // 完成配置的解析，其中store方面有默认值
		sandboxes:       sandboxTable{},
		svcRecords:      make(map[string]svcInfo),
		serviceBindings: make(map[serviceKey]*service),
		agentInitDone:   make(chan struct{}),
		networkLocker:   locker.New(),
	}

	// 初始化Store的过程非常重要，一方面通过store的配置信息完成多种store的初始化，local和global(如果有必要的话)
	// 开始对store进行监控，watch，
	if err := c.initStores(); err != nil {
		return nil, err
	}

	// 初始化驱动存储仓库，只是注册了几个notify func
	drvRegistry, err := drvregistry.New(c.getStore(datastore.LocalScope), c.getStore(datastore.GlobalScope), c.RegisterDriver, nil, c.cfg.PluginGetter)
	if err != nil {
		return nil, err
	}

	for _, i := range getInitializers(c.cfg.Daemon.Experimental) {
		// getInitializers 返回各类driver的初始化函数，比如{overlay.Init, "overlay"}
		// type initializer struct {
		//     fn    drvregistry.InitFunc // overlay.Init
		//     ntype string // "overlay"
		// }
		var dcfg map[string]interface{}

		// External plugins don't need config passed through daemon. They can
		// bootstrap themselves
		if i.ntype != "remote" {
			dcfg = c.makeDriverConfig(i.ntype)
		}

		// 在空的网络驱动存储仓库中，添加具体的驱动，比如bridge，host，overlay，macvlan...
		if err := drvRegistry.AddDriver(i.ntype, i.fn, dcfg); err != nil {
			return nil, err
		}
	}

	// 初始化ipamDriver，也就是不同的网络地址空间分配器allocator
	// 并将allocator存储在drvRegistry中
	if err = initIPAMDrivers(drvRegistry, nil, c.getStore(datastore.GlobalScope)); err != nil {
		return nil, err
	}

	c.drvRegistry = drvRegistry

	if c.cfg != nil && c.cfg.Cluster.Watcher != nil {
		if err := c.initDiscovery(c.cfg.Cluster.Watcher); err != nil {
			// Failing to initialize discovery is a bad situation to be in.
			// But it cannot fail creating the Controller
			logrus.Errorf("Failed to Initialize Discovery : %v", err)
		}
	}

	// 遍历libnetwork管理的所有network实例，对实例执行 populateSpecial 操作
	// populateSpecial就看网络network是否是host或者null，若是，则说明时SpecialDriver，
	// 需要创建该网络，并添加到controller中
	c.WalkNetworks(populateSpecial)

	// Reserve pools first before doing cleanup. Otherwise the
	// cleanups of endpoint/network and sandbox below will
	// generate many unnecessary warnings

	// 从store拿出所有的network的，也是在初始化阶段，
	// 通过store的中network信息，来初始化allocator的网络地址空间，也相当于预留地址空间
	c.reservePools()

	// Cleanup resources
	c.sandboxCleanup(c.cfg.ActiveSandboxes)

	// 重新加载endpoint的信息
	c.cleanupLocalEndpoints()
	c.networkCleanup()

	if err := c.startExternalKeyListener(); err != nil {
		return nil, err
	}

	return c, nil
}

// docker swarm init时会初始化cluster对象，初始化时需要 startNewNode，startNewNode过程中要为
// cluster设置集群提供能力，也就是daemon.SetClusterProvider，随即变成libnetwork.Controller的SetClusterProvider
func (c *controller) SetClusterProvider(provider cluster.Provider) {
	c.Lock()
	c.cfg.Daemon.ClusterProvider = provider
	disableProviderCh := c.cfg.Daemon.DisableProvider
	c.Unlock()
	if provider != nil {
		// 如果是集群模式，需要初始化agent
		// 开始初始化 agent
		go c.clusterAgentInit()
	} else {
		// 如果集群提供能力为空，则需要停止集群能力的运行
		disableProviderCh <- struct{}{}
	}
}

func isValidClusteringIP(addr string) bool {
	return addr != "" && !net.ParseIP(addr).IsLoopback() && !net.ParseIP(addr).IsUnspecified()
}

// libnetwork side of agent depends on the keys. On the first receipt of
// keys setup the agent. For subsequent key set handle the key change
func (c *controller) SetKeys(keys []*types.EncryptionKey) error {
	c.Lock()
	existingKeys := c.keys
	clusterConfigAvailable := c.clusterConfigAvailable
	agent := c.agent
	c.Unlock()

	subsysKeys := make(map[string]int)
	for _, key := range keys {
		if key.Subsystem != subsysGossip &&
			key.Subsystem != subsysIPSec {
			return fmt.Errorf("key received for unrecognized subsystem")
		}
		subsysKeys[key.Subsystem]++
	}
	for s, count := range subsysKeys {
		if count != keyringSize {
			return fmt.Errorf("incorrect number of keys for subsystem %v", s)
		}
	}

	if len(existingKeys) == 0 {
		c.Lock()
		c.keys = keys
		c.Unlock()
		if agent != nil {
			return (fmt.Errorf("libnetwork agent setup without keys"))
		}
		if clusterConfigAvailable {
			return c.agentSetup()
		}
		logrus.Debug("received encryption keys before cluster config")
		return nil
	}
	if agent == nil {
		c.Lock()
		c.keys = keys
		c.Unlock()
		return nil
	}
	return c.handleKeyChange(keys)
}

func (c *controller) getAgent() *agent {
	c.Lock()
	defer c.Unlock()
	return c.agent
}

func (c *controller) clusterAgentInit() {
	clusterProvider := c.cfg.Daemon.ClusterProvider
	for {
		select {
		// clusterProvider.ListenClusterEvents()为管道，该管道接收集群参与者变化的消息，
		// 当startNewNode 时，clusterProvider.configEvent会被传入值
		//（见docker/daemon/cluster.go#L335）
		// 所以一启动，这里就可以往下执行agentSetup
		case <-clusterProvider.ListenClusterEvents():
			if !c.isDistributedControl() {
				c.Lock()
				c.clusterConfigAvailable = true
				keys := c.keys
				c.Unlock()
				// agent initialization needs encryption keys and bind/remote IP which
				// comes from the daemon cluster events
				if len(keys) > 0 {
					c.agentSetup()
				}
			}
		case <-c.cfg.Daemon.DisableProvider:
			// 开始关闭libnetwork的集群能力
			c.Lock()
			c.clusterConfigAvailable = false
			c.agentInitDone = make(chan struct{})
			c.keys = nil
			c.Unlock()

			// We are leaving the cluster. Make sure we
			// close the gossip so that we stop all
			// incoming gossip updates before cleaning up
			// any remaining service bindings. But before
			// deleting the networks since the networks
			// should still be present when cleaning up
			// service bindings
			c.agentClose()
			// 删除所有service与负载均衡以及ingress的绑定
			c.cleanupServiceBindings("")

			c.clearIngress(true)

			return
		}
	}
}

// AgentInitWait waits for agent initialization to be completed in the
// controller.
func (c *controller) AgentInitWait() {
	c.Lock()
	agentInitDone := c.agentInitDone
	c.Unlock()

	if agentInitDone != nil {
		<-agentInitDone
	}
}

// 为每种类型的 network driver 生成网络驱动配置
func (c *controller) makeDriverConfig(ntype string) map[string]interface{} {
	if c.cfg == nil {
		return nil
	}

	config := make(map[string]interface{})

	// 把标签配置解析出来，放入最终需要返回的config中
	for _, label := range c.cfg.Daemon.Labels {
		if !strings.HasPrefix(netlabel.Key(label), netlabel.DriverPrefix+"."+ntype) {
			continue
		}

		config[netlabel.Key(label)] = netlabel.Value(label)
	}

	// 取出用户指定的相应类型网络驱动的配置，用户输入的原始数据
	// 用户可以配置c.cfg.Daemon.DriverCfg，实际上在docker daemon中，docker仅仅
	// 允许配置bridge网络驱动的参数
	drvCfg, ok := c.cfg.Daemon.DriverCfg[ntype]
	if ok {
		for k, v := range drvCfg.(map[string]interface{}) {
			config[k] = v
		}
	}

	// 这一部分，根据libnetwork.controller的store参数来初始化网络驱动的配置参数
	// 默认只有一个local的Scope
	for k, v := range c.cfg.Scopes {
		if !v.IsValid() {
			continue
		}
		config[netlabel.MakeKVClient(k)] = discoverapi.DatastoreConfigData{
			Scope:    k,
			Provider: v.Client.Provider,
			Address:  v.Client.Address,
			Config:   v.Client.Config,
		}
	}

	return config
}

var procReloadConfig = make(chan (bool), 1)

func (c *controller) ReloadConfiguration(cfgOptions ...config.Option) error {
	procReloadConfig <- true
	defer func() { <-procReloadConfig }()

	// For now we accept the configuration reload only as a mean to provide a global store config after boot.
	// Refuse the configuration if it alters an existing datastore client configuration.
	update := false
	cfg := config.ParseConfigOptions(cfgOptions...)

	for s := range c.cfg.Scopes {
		if _, ok := cfg.Scopes[s]; !ok {
			return types.ForbiddenErrorf("cannot accept new configuration because it removes an existing datastore client")
		}
	}
	for s, nSCfg := range cfg.Scopes {
		if eSCfg, ok := c.cfg.Scopes[s]; ok {
			if eSCfg.Client.Provider != nSCfg.Client.Provider ||
				eSCfg.Client.Address != nSCfg.Client.Address {
				return types.ForbiddenErrorf("cannot accept new configuration because it modifies an existing datastore client")
			}
		} else {
			if err := c.initScopedStore(s, nSCfg); err != nil {
				return err
			}
			update = true
		}
	}
	if !update {
		return nil
	}

	c.Lock()
	c.cfg = cfg
	c.Unlock()

	var dsConfig *discoverapi.DatastoreConfigData
	for scope, sCfg := range cfg.Scopes {
		if scope == datastore.LocalScope || !sCfg.IsValid() {
			continue
		}
		dsConfig = &discoverapi.DatastoreConfigData{
			Scope:    scope,
			Provider: sCfg.Client.Provider,
			Address:  sCfg.Client.Address,
			Config:   sCfg.Client.Config,
		}
		break
	}
	if dsConfig == nil {
		return nil
	}

	c.drvRegistry.WalkIPAMs(func(name string, driver ipamapi.Ipam, cap *ipamapi.Capability) bool {
		err := driver.DiscoverNew(discoverapi.DatastoreConfig, *dsConfig)
		if err != nil {
			logrus.Errorf("Failed to set datastore in driver %s: %v", name, err)
		}
		return false
	})

	c.drvRegistry.WalkDrivers(func(name string, driver driverapi.Driver, capability driverapi.Capability) bool {
		err := driver.DiscoverNew(discoverapi.DatastoreConfig, *dsConfig)
		if err != nil {
			logrus.Errorf("Failed to set datastore in driver %s: %v", name, err)
		}
		return false
	})

	if c.discovery == nil && c.cfg.Cluster.Watcher != nil {
		if err := c.initDiscovery(c.cfg.Cluster.Watcher); err != nil {
			logrus.Errorf("Failed to Initialize Discovery after configuration update: %v", err)
		}
	}

	return nil
}

func (c *controller) ID() string {
	return c.id
}

func (c *controller) BuiltinDrivers() []string {
	drivers := []string{}
	c.drvRegistry.WalkDrivers(func(name string, driver driverapi.Driver, capability driverapi.Capability) bool {
		if driver.IsBuiltIn() {
			drivers = append(drivers, name)
		}
		return false
	})
	return drivers
}

func (c *controller) BuiltinIPAMDrivers() []string {
	drivers := []string{}
	c.drvRegistry.WalkIPAMs(func(name string, driver ipamapi.Ipam, cap *ipamapi.Capability) bool {
		if driver.IsBuiltIn() {
			drivers = append(drivers, name)
		}
		return false
	})
	return drivers
}

func (c *controller) validateHostDiscoveryConfig() bool {
	if c.cfg == nil || c.cfg.Cluster.Discovery == "" || c.cfg.Cluster.Address == "" {
		return false
	}
	return true
}

func (c *controller) clusterHostID() string {
	c.Lock()
	defer c.Unlock()
	if c.cfg == nil || c.cfg.Cluster.Address == "" {
		return ""
	}
	addr := strings.Split(c.cfg.Cluster.Address, ":")
	return addr[0]
}

func (c *controller) isNodeAlive(node string) bool {
	if c.discovery == nil {
		return false
	}

	nodes := c.discovery.Fetch()
	for _, n := range nodes {
		if n.String() == node {
			return true
		}
	}

	return false
}

func (c *controller) initDiscovery(watcher discovery.Watcher) error {
	if c.cfg == nil {
		return fmt.Errorf("discovery initialization requires a valid configuration")
	}

	// 新建一个discovery对象实例
	c.discovery = hostdiscovery.NewHostDiscovery(watcher)
	// 立即开始监听节点的新加入、退出等事件
	return c.discovery.Watch(c.activeCallback, c.hostJoinCallback, c.hostLeaveCallback)
}

func (c *controller) activeCallback() {
	ds := c.getStore(datastore.GlobalScope)
	if ds != nil && !ds.Active() {
		ds.RestartWatch()
	}
}

// 当有节点加入集群的时候，hostdiscovery监听到事件，随后回调这个函数
func (c *controller) hostJoinCallback(nodes []net.IP) {
	c.processNodeDiscovery(nodes, true)
}

// 当有节点离开集群的时候，hostdiscovery监听到事件，随后回调这个函数
func (c *controller) hostLeaveCallback(nodes []net.IP) {
	c.processNodeDiscovery(nodes, false)
}

func (c *controller) processNodeDiscovery(nodes []net.IP, add bool) {
	c.drvRegistry.WalkDrivers(func(name string, driver driverapi.Driver, capability driverapi.Capability) bool {
		c.pushNodeDiscovery(driver, capability, nodes, add)
		return false
	})
}

func (c *controller) pushNodeDiscovery(d driverapi.Driver, cap driverapi.Capability, nodes []net.IP, add bool) {
	var self net.IP
	if c.cfg != nil {
		addr := strings.Split(c.cfg.Cluster.Address, ":")
		self = net.ParseIP(addr[0])
		// if external kvstore is not configured, try swarm-mode config
		if self == nil {
			if agent := c.getAgent(); agent != nil {
				self = net.ParseIP(agent.advertiseAddr)
			}
		}
	}

	if d == nil || cap.DataScope != datastore.GlobalScope || nodes == nil {
		return
	}

	for _, node := range nodes {
		nodeData := discoverapi.NodeDiscoveryData{Address: node.String(), Self: node.Equal(self)}
		var err error
		if add {
			err = d.DiscoverNew(discoverapi.NodeDiscovery, nodeData)
		} else {
			err = d.DiscoverDelete(discoverapi.NodeDiscovery, nodeData)
		}
		if err != nil {
			logrus.Debugf("discovery notification error: %v", err)
		}
	}
}

func (c *controller) Config() config.Config {
	c.Lock()
	defer c.Unlock()
	if c.cfg == nil {
		return config.Config{}
	}
	return *c.cfg
}

func (c *controller) isManager() bool {
	c.Lock()
	defer c.Unlock()
	if c.cfg == nil || c.cfg.Daemon.ClusterProvider == nil {
		return false
	}
	return c.cfg.Daemon.ClusterProvider.IsManager()
}

func (c *controller) isAgent() bool {
	c.Lock()
	defer c.Unlock()
	// 如果不是Swarm Mode的集群模式，那么返回false，即不是agent
	if c.cfg == nil || c.cfg.Daemon.ClusterProvider == nil {
		return false
	}
	return c.cfg.Daemon.ClusterProvider.IsAgent()
}

func (c *controller) isDistributedControl() bool {
	// 如果本节点不是swarm集群中的manager，也不是agent
	return !c.isManager() && !c.isAgent()
}

func (c *controller) GetPluginGetter() plugingetter.PluginGetter {
	return c.drvRegistry.GetPluginGetter()
}

func (c *controller) RegisterDriver(networkType string, driver driverapi.Driver, capability driverapi.Capability) error {
	c.Lock()
	hd := c.discovery
	c.Unlock()

	if hd != nil {
		c.pushNodeDiscovery(driver, capability, hd.Fetch(), true)
	}

	c.agentDriverNotify(driver)
	return nil
}

// NewNetwork creates a new network of the specified network type. The options
// are network specific and modeled in a generic way.
func (c *controller) NewNetwork(networkType, name string, id string, options ...NetworkOption) (Network, error) {
	if id != "" {
		c.networkLocker.Lock(id)
		defer c.networkLocker.Unlock(id)

		if _, err := c.NetworkByID(id); err == nil {
			return nil, NetworkNameError(id)
		}
	}

	if !config.IsValidName(name) {
		return nil, ErrInvalidName(name)
	}

	if id == "" {
		id = stringid.GenerateRandomID()
	}

	defaultIpam := defaultIpamForNetworkType(networkType)
	// Construct the network object
	// 新建一个libnetwork管理层面的网络对象，并不代表有具体driver的network
	// 具体的network在每个driver中，在drvregistry中
	network := &network{
		name:        name,
		networkType: networkType,
		generic:     map[string]interface{}{netlabel.GenericData: make(map[string]string)},
		ipamType:    defaultIpam, // "default"
		id:          id,
		created:     time.Now(),
		ctrlr:       c,
		persist:     true,
		drvOnce:     &sync.Once{},
	}

	network.processOptions(options...)

	_, cap, err := network.resolveDriver(networkType, true)
	if err != nil {
		return nil, err
	}

	if network.ingress && cap.DataScope != datastore.GlobalScope {
		return nil, types.ForbiddenErrorf("Ingress network can only be global scope network")
	}

	if cap.DataScope == datastore.GlobalScope && !c.isDistributedControl() && !network.dynamic {
		if c.isManager() {
			// For non-distributed controlled environment, globalscoped non-dynamic networks are redirected to Manager
			return nil, ManagerRedirectError(name)
		}

		return nil, types.ForbiddenErrorf("Cannot create a multi-host network from a worker node. Please create the network from a manager node.")
	}

	// Make sure we have a driver available for this network type
	// before we allocate anything.
	if _, err := network.driver(true); err != nil {
		return nil, err
	}

	// 通过相对应的ipam为network分配网络地址
	err = network.ipamAllocate()
	if err != nil {
		return nil, err
	}

	defer func() {
		// 如果这次新建工作失败了，那么ipam需要把相应的资源回收
		if err != nil {
			network.ipamRelease()
		}
	}()

	// 刚才仅仅是初始化network对象，并通过network的ipamV4Config在ipam/allocator中申请地址
	// addNetwork 现在是要通过具体的driver来创建实际的网络network
	err = c.addNetwork(network)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			// 如果创建网络过程中失败，则需要删除网络
			if e := network.deleteNetwork(); e != nil {
				logrus.Warnf("couldn't roll back driver network on network %s creation failure: %v", network.name, err)
			}
		}
	}()

	// First store the endpoint count, then the network. To avoid to
	// end up with a datastore containing a network and not an epCnt,
	// in case of an ungraceful shutdown during this function call.
	epCnt := &endpointCnt{n: network}

	// 将endpointCnt更新到store中
	if err = c.updateToStore(epCnt); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			if e := c.deleteFromStore(epCnt); e != nil {
				logrus.Warnf("could not rollback from store, epCnt %v on failure (%v): %v", epCnt, err, e)
			}
		}
	}()

	network.epCnt = epCnt

	// 将network更新到store中
	if err = c.updateToStore(network); err != nil {
		return nil, err
	}

	// 是否有必要所有的network，都要执行n.joinCluster()
	// 因为n.joinCluster()需要networkdb添加这个网络，并触发一个事件
	// 最终会将网络的信息在网络间gossip传播
	joinCluster(network)

	if !c.isDistributedControl() {
		c.Lock()
		arrangeIngressFilterRule()
		c.Unlock()
	}

	return network, nil
}

var joinCluster NetworkWalker = func(nw Network) bool {
	n := nw.(*network)
	if err := n.joinCluster(); err != nil {
		logrus.Errorf("Failed to join network %s (%s) into agent cluster: %v", n.Name(), n.ID(), err)
	}
	n.addDriverWatches()
	return false
}

func (c *controller) reservePools() {
	// 从store拿出所有的network的，也是在初始化阶段，
	// 通过store的中network信息，来初始化allocator的网络地址空间，也相当于预留地址空间
	networks, err := c.getNetworksForScope(datastore.LocalScope)
	if err != nil {
		logrus.Warnf("Could not retrieve networks from local store during ipam allocation for existing networks: %v", err)
		return
	}

	for _, n := range networks {
		if !doReplayPoolReserve(n) {
			continue
		}
		// Construct pseudo configs for the auto IP case
		autoIPv4 := (len(n.ipamV4Config) == 0 || (len(n.ipamV4Config) == 1 && n.ipamV4Config[0].PreferredPool == "")) && len(n.ipamV4Info) > 0
		autoIPv6 := (len(n.ipamV6Config) == 0 || (len(n.ipamV6Config) == 1 && n.ipamV6Config[0].PreferredPool == "")) && len(n.ipamV6Info) > 0
		if autoIPv4 {
			n.ipamV4Config = []*IpamConf{{PreferredPool: n.ipamV4Info[0].Pool.String()}}
		}
		if n.enableIPv6 && autoIPv6 {
			n.ipamV6Config = []*IpamConf{{PreferredPool: n.ipamV6Info[0].Pool.String()}}
		}
		// Account current network gateways
		for i, c := range n.ipamV4Config {
			if c.Gateway == "" && n.ipamV4Info[i].Gateway != nil {
				c.Gateway = n.ipamV4Info[i].Gateway.IP.String()
			}
		}
		if n.enableIPv6 {
			for i, c := range n.ipamV6Config {
				if c.Gateway == "" && n.ipamV6Info[i].Gateway != nil {
					c.Gateway = n.ipamV6Info[i].Gateway.IP.String()
				}
			}
		}

		// Reserve pools，
		// 将network中的信息，进行分配，也就是在allocator的地址空间中预留这些地址
		if err := n.ipamAllocate(); err != nil {
			logrus.Warnf("Failed to allocate ipam pool(s) for network %q (%s): %v", n.Name(), n.ID(), err)
		}
		// Reserve existing endpoints' addresses
		ipam, _, err := n.getController().getIPAMDriver(n.ipamType)
		if err != nil {
			logrus.Warnf("Failed to retrieve ipam driver for network %q (%s) during address reservation", n.Name(), n.ID())
			continue
		}
		epl, err := n.getEndpointsFromStore()
		if err != nil {
			logrus.Warnf("Failed to retrieve list of current endpoints on network %q (%s)", n.Name(), n.ID())
			continue
		}
		for _, ep := range epl {
			// 将endpoint的网络地址信息在allocator中预留
			if err := ep.assignAddress(ipam, true, ep.Iface().AddressIPv6() != nil); err != nil {
				logrus.Warnf("Failed to reserve current address for endpoint %q (%s) on network %q (%s)",
					ep.Name(), ep.ID(), n.Name(), n.ID())
			}
		}
	}
}

func doReplayPoolReserve(n *network) bool {
	_, caps, err := n.getController().getIPAMDriver(n.ipamType)
	if err != nil {
		logrus.Warnf("Failed to retrieve ipam driver for network %q (%s): %v", n.Name(), n.ID(), err)
		return false
	}
	return caps.RequiresRequestReplay
}

func (c *controller) addNetwork(n *network) error {
	// 通过network中的networkType，获取相应的driver
	d, err := n.driver(true)
	if err != nil {
		return err
	}

	// Create the network
	// 通过具体的driver来创建network，传入的数据是id，generic，以及ipv4和ipv6的IPamData
	if err := d.CreateNetwork(n.id, n.generic, n, n.getIPData(4), n.getIPData(6)); err != nil {
		return err
	}

	// 通过具体的driver创建完network之后
	// 需要开始启动一个网络内部的dns解析功能
	n.startResolver()

	return nil
}

func (c *controller) Networks() []Network {
	var list []Network

	networks, err := c.getNetworksFromStore()
	if err != nil {
		logrus.Error(err)
	}

	// 查看libnetwork管理的所有网络，
	// 如果这些网络中有些正处于删除阶段，则不予考虑在内
	for _, n := range networks {
		if n.inDelete {
			continue
		}
		list = append(list, n)
	}

	return list
}

func (c *controller) WalkNetworks(walker NetworkWalker) {
	for _, n := range c.Networks() {
		if walker(n) {
			return
		}
	}
}

func (c *controller) NetworkByName(name string) (Network, error) {
	if name == "" {
		return nil, ErrInvalidName(name)
	}
	var n Network

	s := func(current Network) bool {
		if current.Name() == name {
			n = current
			return true
		}
		return false
	}

	c.WalkNetworks(s)

	if n == nil {
		return nil, ErrNoSuchNetwork(name)
	}

	return n, nil
}

// 通过用户传入的ID，获取在Store中存储的network信息，
// 这个事controller层面的network，并非是driver层面的network
func (c *controller) NetworkByID(id string) (Network, error) {
	if id == "" {
		return nil, ErrInvalidID(id)
	}

	n, err := c.getNetworkFromStore(id)
	if err != nil {
		return nil, ErrNoSuchNetwork(id)
	}

	return n, nil
}

// NewSandbox creates a new sandbox for the passed container id
func (c *controller) NewSandbox(containerID string, options ...SandboxOption) (sBox Sandbox, err error) {
	if containerID == "" {
		return nil, types.BadRequestErrorf("invalid container ID")
	}

	var sb *sandbox
	c.Lock()
	for _, s := range c.sandboxes {
		if s.containerID == containerID {
			// If not a stub, then we already have a complete sandbox.
			if !s.isStub {
				sbID := s.ID()
				c.Unlock()
				return nil, types.ForbiddenErrorf("container %s is already present in sandbox %s", containerID, sbID)
			}

			// We already have a stub sandbox from the
			// store. Make use of it so that we don't lose
			// the endpoints from store but reset the
			// isStub flag.
			sb = s
			sb.isStub = false
			break
		}
	}
	c.Unlock()

	// Create sandbox and process options first. Key generation depends on an option
	if sb == nil {
		sb = &sandbox{
			id:                 stringid.GenerateRandomID(),
			containerID:        containerID,
			endpoints:          epHeap{},
			epPriority:         map[string]int{},
			populatedEndpoints: map[string]struct{}{},
			config:             containerConfig{},
			controller:         c,
			extDNS:             []extDNSEntry{},
		}
	}
	sBox = sb

	heap.Init(&sb.endpoints)

	sb.processOptions(options...)

	c.Lock()
	if sb.ingress && c.ingressSandbox != nil {
		c.Unlock()
		return nil, types.ForbiddenErrorf("ingress sandbox already present")
	}

	if sb.ingress {
		c.ingressSandbox = sb
		sb.id = "ingress_sbox"
	}
	c.Unlock()
	defer func() {
		if err != nil {
			c.Lock()
			if sb.ingress {
				c.ingressSandbox = nil
			}
			c.Unlock()
		}
	}()

	// 为sandbox设置域名解析所需要的所有文件，
	// 包括 /etc/hosts, /etc/resolv.conf
	if err = sb.setupResolutionFiles(); err != nil {
		return nil, err
	}

	if sb.config.useDefaultSandBox {
		c.sboxOnce.Do(func() {
			c.defOsSbox, err = osl.NewSandbox(sb.Key(), false, false)
		})

		if err != nil {
			c.sboxOnce = sync.Once{}
			return nil, fmt.Errorf("failed to create default sandbox: %v", err)
		}

		sb.osSbox = c.defOsSbox
	}

	if sb.osSbox == nil && !sb.config.useExternalKey {
		if sb.osSbox, err = osl.NewSandbox(sb.Key(), !sb.config.useDefaultSandBox, false); err != nil {
			return nil, fmt.Errorf("failed to create new osl sandbox: %v", err)
		}
	}

	c.Lock()
	c.sandboxes[sb.id] = sb
	c.Unlock()
	defer func() {
		if err != nil {
			c.Lock()
			delete(c.sandboxes, sb.id)
			c.Unlock()
		}
	}()

	err = sb.storeUpdate()
	if err != nil {
		return nil, fmt.Errorf("failed to update the store state of sandbox: %v", err)
	}

	return sb, nil
}

func (c *controller) Sandboxes() []Sandbox {
	c.Lock()
	defer c.Unlock()

	list := make([]Sandbox, 0, len(c.sandboxes))
	for _, s := range c.sandboxes {
		// Hide stub sandboxes from libnetwork users
		if s.isStub {
			continue
		}

		list = append(list, s)
	}

	return list
}

func (c *controller) WalkSandboxes(walker SandboxWalker) {
	for _, sb := range c.Sandboxes() {
		if walker(sb) {
			return
		}
	}
}

func (c *controller) SandboxByID(id string) (Sandbox, error) {
	if id == "" {
		return nil, ErrInvalidID(id)
	}
	c.Lock()
	s, ok := c.sandboxes[id]
	c.Unlock()
	if !ok {
		return nil, types.NotFoundErrorf("sandbox %s not found", id)
	}
	return s, nil
}

// SandboxDestroy destroys a sandbox given a container ID
func (c *controller) SandboxDestroy(id string) error {
	var sb *sandbox
	c.Lock()
	for _, s := range c.sandboxes {
		if s.containerID == id {
			sb = s
			break
		}
	}
	c.Unlock()

	// It is not an error if sandbox is not available
	if sb == nil {
		return nil
	}

	return sb.Delete()
}

// SandboxContainerWalker returns a Sandbox Walker function which looks for an existing Sandbox with the passed containerID
func SandboxContainerWalker(out *Sandbox, containerID string) SandboxWalker {
	return func(sb Sandbox) bool {
		if sb.ContainerID() == containerID {
			*out = sb
			return true
		}
		return false
	}
}

// SandboxKeyWalker returns a Sandbox Walker function which looks for an existing Sandbox with the passed key
func SandboxKeyWalker(out *Sandbox, key string) SandboxWalker {
	return func(sb Sandbox) bool {
		if sb.Key() == key {
			*out = sb
			return true
		}
		return false
	}
}

func (c *controller) loadDriver(networkType string) error {
	var err error

	if pg := c.GetPluginGetter(); pg != nil {
		_, err = pg.Get(networkType, driverapi.NetworkPluginEndpointType, plugingetter.Lookup)
	} else {
		_, err = plugins.Get(networkType, driverapi.NetworkPluginEndpointType)
	}

	if err != nil {
		if err == plugins.ErrNotFound {
			return types.NotFoundErrorf(err.Error())
		}
		return err
	}

	return nil
}

func (c *controller) loadIPAMDriver(name string) error {
	var err error

	if pg := c.GetPluginGetter(); pg != nil {
		_, err = pg.Get(name, ipamapi.PluginEndpointType, plugingetter.Lookup)
	} else {
		_, err = plugins.Get(name, ipamapi.PluginEndpointType)
	}

	if err != nil {
		if err == plugins.ErrNotFound {
			return types.NotFoundErrorf(err.Error())
		}
		return err
	}

	return nil
}

func (c *controller) getIPAMDriver(name string) (ipamapi.Ipam, *ipamapi.Capability, error) {
	id, cap := c.drvRegistry.IPAM(name)
	if id == nil {
		// Might be a plugin name. Try loading it
		if err := c.loadIPAMDriver(name); err != nil {
			return nil, nil, err
		}

		// Now that we resolved the plugin, try again looking up the registry
		id, cap = c.drvRegistry.IPAM(name)
		if id == nil {
			return nil, nil, types.BadRequestErrorf("invalid ipam driver: %q", name)
		}
	}

	return id, cap, nil
}

func (c *controller) Stop() {
	c.clearIngress(false)
	c.closeStores()
	c.stopExternalKeyListener()
	osl.GC()
}

func (c *controller) clearIngress(clusterLeave bool) {
	c.Lock()
	ingressSandbox := c.ingressSandbox
	c.ingressSandbox = nil
	c.Unlock()

	var n *network
	if ingressSandbox != nil {
		for _, ep := range ingressSandbox.getConnectedEndpoints() {
			if nw := ep.getNetwork(); nw.ingress {
				n = nw
				break
			}
		}
		if err := ingressSandbox.Delete(); err != nil {
			logrus.Warnf("Could not delete ingress sandbox while leaving: %v", err)
		}
	}

	if n == nil {
		for _, nw := range c.Networks() {
			if nw.Info().Ingress() {
				n = nw.(*network)
				break
			}
		}
	}
	if n == nil && clusterLeave {
		logrus.Warnf("Could not find ingress network while leaving")
	}

	if n != nil {
		if err := n.Delete(); err != nil {
			logrus.Warnf("Could not delete ingress network while leaving: %v", err)
		}
	}
}
