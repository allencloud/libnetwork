package networkdb

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	rnd "math/rand"
	"net"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/memberlist"
)

const (
	reapInterval     = 60 * time.Second
	reapPeriod       = 5 * time.Second
	retryInterval    = 1 * time.Second
	nodeReapInterval = 24 * time.Hour
	nodeReapPeriod   = 2 * time.Hour
)

type logWriter struct{}

func (l *logWriter) Write(p []byte) (int, error) {
	str := string(p)
	str = strings.TrimSuffix(str, "\n")

	switch {
	case strings.HasPrefix(str, "[WARN] "):
		str = strings.TrimPrefix(str, "[WARN] ")
		logrus.Warn(str)
	case strings.HasPrefix(str, "[DEBUG] "):
		str = strings.TrimPrefix(str, "[DEBUG] ")
		logrus.Debug(str)
	case strings.HasPrefix(str, "[INFO] "):
		str = strings.TrimPrefix(str, "[INFO] ")
		logrus.Info(str)
	case strings.HasPrefix(str, "[ERR] "):
		str = strings.TrimPrefix(str, "[ERR] ")
		logrus.Warn(str)
	}

	return len(p), nil
}

// SetKey adds a new key to the key ring
func (nDB *NetworkDB) SetKey(key []byte) {
	logrus.Debugf("Adding key %s", hex.EncodeToString(key)[0:5])
	nDB.Lock()
	defer nDB.Unlock()
	for _, dbKey := range nDB.config.Keys {
		if bytes.Equal(key, dbKey) {
			return
		}
	}
	nDB.config.Keys = append(nDB.config.Keys, key)
	if nDB.keyring != nil {
		nDB.keyring.AddKey(key)
	}
}

// SetPrimaryKey sets the given key as the primary key. This should have
// been added apriori through SetKey
func (nDB *NetworkDB) SetPrimaryKey(key []byte) {
	logrus.Debugf("Primary Key %s", hex.EncodeToString(key)[0:5])
	nDB.RLock()
	defer nDB.RUnlock()
	for _, dbKey := range nDB.config.Keys {
		if bytes.Equal(key, dbKey) {
			if nDB.keyring != nil {
				nDB.keyring.UseKey(dbKey)
			}
			break
		}
	}
}

// RemoveKey removes a key from the key ring. The key being removed
// can't be the primary key
func (nDB *NetworkDB) RemoveKey(key []byte) {
	logrus.Debugf("Remove Key %s", hex.EncodeToString(key)[0:5])
	nDB.Lock()
	defer nDB.Unlock()
	for i, dbKey := range nDB.config.Keys {
		if bytes.Equal(key, dbKey) {
			nDB.config.Keys = append(nDB.config.Keys[:i], nDB.config.Keys[i+1:]...)
			if nDB.keyring != nil {
				nDB.keyring.RemoveKey(dbKey)
			}
			break
		}
	}
}

// 针对每新建的一个network controller，需要加入集群模式；网络需要创建networkdb
// 创建完之后，需要对networkdb进行集群范围内的初始化，包括获取集群内其他的节点信息等
func (nDB *NetworkDB) clusterInit() error {
	// 创建默认的局域网memberlist配置信息，并加入一些特定的配置项
	config := memberlist.DefaultLANConfig()
	config.Name = nDB.config.NodeName
	config.BindAddr = nDB.config.BindAddr
	config.AdvertiseAddr = nDB.config.AdvertiseAddr

	if nDB.config.BindPort != 0 {
		config.BindPort = nDB.config.BindPort
	}

	config.ProtocolVersion = memberlist.ProtocolVersionMax
	config.Delegate = &delegate{nDB: nDB}
	config.Events = &eventDelegate{nDB: nDB}
	// custom logger that does not add time or date, so they are not
	// duplicated by logrus
	config.Logger = log.New(&logWriter{}, "", 0)

	var err error
	if len(nDB.config.Keys) > 0 {
		for i, key := range nDB.config.Keys {
			logrus.Debugf("Encryption key %d: %s", i+1, hex.EncodeToString(key)[0:5])
		}
		nDB.keyring, err = memberlist.NewKeyring(nDB.config.Keys, nDB.config.Keys[0])
		if err != nil {
			return err
		}
		config.Keyring = nDB.keyring
	}

	nDB.networkBroadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			nDB.RLock()
			num := len(nDB.nodes)
			nDB.RUnlock()
			return num
		},
		RetransmitMult: config.RetransmitMult,
	}

	nDB.nodeBroadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			nDB.RLock()
			num := len(nDB.nodes)
			nDB.RUnlock()
			return num
		},
		RetransmitMult: config.RetransmitMult,
	}

	// 开始真正新建一个memberlist对象，维护一个集群成员列表
	mlist, err := memberlist.Create(config)
	if err != nil {
		return fmt.Errorf("failed to create memberlist: %v", err)
	}

	// 把memberlist的信息等，装载进入networkdb
	nDB.stopCh = make(chan struct{})
	nDB.memberlist = mlist

	// 真正的初始化操作应该是在这里吧
	for _, trigger := range []struct {
		interval time.Duration // 主要是用来保障以下的5个方法，不要再同一时间上开始运行
		fn       func()
	}{
		{reapPeriod, nDB.reapState},                   // 每隔5s，就开始清理状态
		{config.GossipInterval, nDB.gossip},           // 每隔200ms, 就开始实现gossip传播协议
		{config.PushPullInterval, nDB.bulkSyncTables}, // 每隔 30s, 实现
		{retryInterval, nDB.reconnectNode},            // 每隔1s时间，就开始重新连接节点
		{nodeReapPeriod, nDB.reapDeadNode},            // 每隔2小时，需要开始执行一个死节点的清理
	} {
		t := time.NewTicker(trigger.interval)
		// 新创建goroutine来执行以上的5个方法
		// 每一个goroutine的运行逻辑是这样的：
		// 1. 根据 trigger.interval 来delay运行指定的函数；
		// 2. 如果 nDB.stopCh 有内容，说明需要停止networkdb的运行，则退出；
		// 3. 如果以上条件都OK，那么每隔定期时间 t.C，开始运行trigger.fn
		go nDB.triggerFunc(trigger.interval, t.C, nDB.stopCh, trigger.fn)
		nDB.tickers = append(nDB.tickers, t)
	}

	return nil
}

func (nDB *NetworkDB) retryJoin(members []string, stop <-chan struct{}) {
	t := time.NewTicker(retryInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if _, err := nDB.memberlist.Join(members); err != nil {
				logrus.Errorf("Failed to join memberlist %s on retry: %v", members, err)
				continue
			}
			if err := nDB.sendNodeEvent(NodeEventTypeJoin); err != nil {
				logrus.Errorf("failed to send node join on retry: %v", err)
				continue
			}
			return
		case <-stop:
			return
		}
	}

}

func (nDB *NetworkDB) clusterJoin(members []string) error {
	mlist := nDB.memberlist

	if _, err := mlist.Join(members); err != nil {
		// Incase of failure, keep retrying join until it succeeds or the cluster is shutdown.
		go nDB.retryJoin(members, nDB.stopCh)

		return fmt.Errorf("could not join node to memberlist: %v", err)
	}

	if err := nDB.sendNodeEvent(NodeEventTypeJoin); err != nil {
		return fmt.Errorf("failed to send node join: %v", err)
	}

	return nil
}

func (nDB *NetworkDB) clusterLeave() error {
	mlist := nDB.memberlist

	if err := nDB.sendNodeEvent(NodeEventTypeLeave); err != nil {
		logrus.Errorf("failed to send node leave: %v", err)
	}

	if err := mlist.Leave(time.Second); err != nil {
		return err
	}

	close(nDB.stopCh)

	for _, t := range nDB.tickers {
		t.Stop()
	}

	return mlist.Shutdown()
}

func (nDB *NetworkDB) triggerFunc(stagger time.Duration, C <-chan time.Time, stop <-chan struct{}, f func()) {
	// Use a random stagger to avoid syncronizing
	randStagger := time.Duration(uint64(rnd.Int63()) % uint64(stagger))
	select {
	case <-time.After(randStagger):
	case <-stop:
		return
	}
	for {
		select {
		case <-C:
			f()
		case <-stop:
			return
		}
	}
}

// 从networkdb的failedNodes中删除失败的节点
func (nDB *NetworkDB) reapDeadNode() {
	nDB.Lock()
	defer nDB.Unlock()
	for id, n := range nDB.failedNodes {
		if n.reapTime > 0 {
			n.reapTime -= nodeReapPeriod
			continue
		}
		// 如果失败节点超出了它的清理预留时间reapTime，则删除之
		logrus.Debugf("Removing failed node %v from gossip cluster", n.Name)
		delete(nDB.failedNodes, id)
	}
}

func (nDB *NetworkDB) reconnectNode() {
	nDB.RLock()
	if len(nDB.failedNodes) == 0 {
		// 如果没有失败的节点，自然也不需要重连
		nDB.RUnlock()
		return
	}

	nodes := make([]*node, 0, len(nDB.failedNodes))
	for _, n := range nDB.failedNodes {
		nodes = append(nodes, n)
	}
	nDB.RUnlock()

	// 随机挑选出nodes中的任意一个
	node := nodes[randomOffset(len(nodes))]
	addr := net.UDPAddr{IP: node.Addr, Port: int(node.Port)}

	// memberlist 向这个随机的节点发送连接请求，
	// 如果Join出错，则返回；
	// 如果没有出错，则该随机节点的信息会进入memberlist
	if _, err := nDB.memberlist.Join([]string{addr.String()}); err != nil {
		return
	}

	// 由于新的节点已经连接上了，memberlist中的nodes已经发生变化，
	// 所以networkdb需要开始广播自身的节点列表
	if err := nDB.sendNodeEvent(NodeEventTypeJoin); err != nil {
		logrus.Errorf("failed to send node join during reconnect: %v", err)
		return
	}

	// Update all the local table state to a new time to
	// force update on the node we are trying to rejoin, just in
	// case that node has these in deleting state still. This is
	// facilitate fast convergence after recovering from a gossip
	// failure.
	nDB.updateLocalTableTime()

	logrus.Debugf("Initiating bulk sync with node %s after reconnect", node.Name)
	nDB.bulkSync([]string{node.Name}, true)
}

// For timing the entry deletion in the repaer APIs that doesn't use monotonic clock
// source (time.Now, Sub etc.) should be avoided. Hence we use reapTime in every
// entry which is set initially to reapInterval and decremented by reapPeriod every time
// the reaper runs. NOTE nDB.reapTableEntries updates the reapTime with a readlock. This
// is safe as long as no other concurrent path touches the reapTime field.
func (nDB *NetworkDB) reapState() {
	nDB.reapNetworks()
	nDB.reapTableEntries()
}

func (nDB *NetworkDB) reapNetworks() {
	nDB.Lock()
	for name, nn := range nDB.networks {
		for id, n := range nn {
			if n.leaving {
				if n.reapTime <= 0 {
					delete(nn, id)
					nDB.deleteNetworkNode(id, name)
					continue
				}
				n.reapTime -= reapPeriod
			}
		}
	}
	nDB.Unlock()
}

func (nDB *NetworkDB) reapTableEntries() {
	var paths []string

	nDB.RLock()
	nDB.indexes[byTable].Walk(func(path string, v interface{}) bool {
		entry, ok := v.(*entry)
		if !ok {
			return false
		}

		if !entry.deleting {
			return false
		}
		if entry.reapTime > 0 {
			entry.reapTime -= reapPeriod
			return false
		}
		paths = append(paths, path)
		return false
	})
	nDB.RUnlock()

	nDB.Lock()
	for _, path := range paths {
		params := strings.Split(path[1:], "/")
		tname := params[0]
		nid := params[1]
		key := params[2]

		if _, ok := nDB.indexes[byTable].Delete(fmt.Sprintf("/%s/%s/%s", tname, nid, key)); !ok {
			logrus.Errorf("Could not delete entry in table %s with network id %s and key %s as it does not exist", tname, nid, key)
		}

		if _, ok := nDB.indexes[byNetwork].Delete(fmt.Sprintf("/%s/%s/%s", nid, tname, key)); !ok {
			logrus.Errorf("Could not delete entry in network %s with table name %s and key %s as it does not exist", nid, tname, key)
		}
	}
	nDB.Unlock()
}

func (nDB *NetworkDB) gossip() {
	networkNodes := make(map[string][]string)
	nDB.RLock()
	thisNodeNetworks := nDB.networks[nDB.config.NodeName]
	for nid := range thisNodeNetworks {
		networkNodes[nid] = nDB.networkNodes[nid]

	}
	nDB.RUnlock()

	for nid, nodes := range networkNodes {
		mNodes := nDB.mRandomNodes(3, nodes)
		bytesAvail := udpSendBuf - compoundHeaderOverhead

		nDB.RLock()
		network, ok := thisNodeNetworks[nid]
		nDB.RUnlock()
		if !ok || network == nil {
			// It is normal for the network to be removed
			// between the time we collect the network
			// attachments of this node and processing
			// them here.
			continue
		}

		broadcastQ := network.tableBroadcasts

		if broadcastQ == nil {
			logrus.Errorf("Invalid broadcastQ encountered while gossiping for network %s", nid)
			continue
		}

		msgs := broadcastQ.GetBroadcasts(compoundOverhead, bytesAvail)
		if len(msgs) == 0 {
			continue
		}

		// Create a compound message
		compound := makeCompoundMessage(msgs)

		for _, node := range mNodes {
			nDB.RLock()
			mnode := nDB.nodes[node]
			nDB.RUnlock()

			if mnode == nil {
				break
			}

			// Send the compound message
			if err := nDB.memberlist.SendToUDP(&mnode.Node, compound); err != nil {
				logrus.Errorf("Failed to send gossip to %s: %s", mnode.Addr, err)
			}
		}
	}
}

func (nDB *NetworkDB) bulkSyncTables() {
	var networks []string
	nDB.RLock()
	for nid, network := range nDB.networks[nDB.config.NodeName] {
		if network.leaving {
			continue
		}
		networks = append(networks, nid)
	}
	nDB.RUnlock()

	for {
		if len(networks) == 0 {
			break
		}

		nid := networks[0]
		networks = networks[1:]

		nDB.RLock()
		nodes := nDB.networkNodes[nid]
		nDB.RUnlock()

		// No peer nodes on this network. Move on.
		if len(nodes) == 0 {
			continue
		}

		completed, err := nDB.bulkSync(nodes, false)
		if err != nil {
			logrus.Errorf("periodic bulk sync failure for network %s: %v", nid, err)
			continue
		}

		// Remove all the networks for which we have
		// successfully completed bulk sync in this iteration.
		updatedNetworks := make([]string, 0, len(networks))
		for _, nid := range networks {
			var found bool
			for _, completedNid := range completed {
				if nid == completedNid {
					found = true
					break
				}
			}

			if !found {
				updatedNetworks = append(updatedNetworks, nid)
			}
		}

		networks = updatedNetworks
	}
}

func (nDB *NetworkDB) bulkSync(nodes []string, all bool) ([]string, error) {
	if !all {
		// If not all, then just pick one.
		nodes = nDB.mRandomNodes(1, nodes)
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	logrus.Debugf("%s: Initiating bulk sync with nodes %v", nDB.config.NodeName, nodes)
	var err error
	var networks []string
	for _, node := range nodes {
		if node == nDB.config.NodeName {
			continue
		}

		networks = nDB.findCommonNetworks(node)
		err = nDB.bulkSyncNode(networks, node, true)
		if err != nil {
			err = fmt.Errorf("bulk sync failed on node %s: %v", node, err)
		}
	}

	if err != nil {
		return nil, err
	}

	return networks, nil
}

// Bulk sync all the table entries belonging to a set of networks to a
// single peer node. It can be unsolicited or can be in response to an
// unsolicited bulk sync
func (nDB *NetworkDB) bulkSyncNode(networks []string, node string, unsolicited bool) error {
	var msgs [][]byte

	var unsolMsg string
	if unsolicited {
		unsolMsg = "unsolicited"
	}

	logrus.Debugf("%s: Initiating %s bulk sync for networks %v with node %s", nDB.config.NodeName, unsolMsg, networks, node)

	nDB.RLock()
	mnode := nDB.nodes[node]
	if mnode == nil {
		nDB.RUnlock()
		return nil
	}

	for _, nid := range networks {
		nDB.indexes[byNetwork].WalkPrefix(fmt.Sprintf("/%s", nid), func(path string, v interface{}) bool {
			entry, ok := v.(*entry)
			if !ok {
				return false
			}

			eType := TableEventTypeCreate
			if entry.deleting {
				eType = TableEventTypeDelete
			}

			params := strings.Split(path[1:], "/")
			tEvent := TableEvent{
				Type:      eType,
				LTime:     entry.ltime,
				NodeName:  entry.node,
				NetworkID: nid,
				TableName: params[1],
				Key:       params[2],
				Value:     entry.value,
			}

			msg, err := encodeMessage(MessageTypeTableEvent, &tEvent)
			if err != nil {
				logrus.Errorf("Encode failure during bulk sync: %#v", tEvent)
				return false
			}

			msgs = append(msgs, msg)
			return false
		})
	}
	nDB.RUnlock()

	// Create a compound message
	compound := makeCompoundMessage(msgs)

	bsm := BulkSyncMessage{
		LTime:       nDB.tableClock.Time(),
		Unsolicited: unsolicited,
		NodeName:    nDB.config.NodeName,
		Networks:    networks,
		Payload:     compound,
	}

	buf, err := encodeMessage(MessageTypeBulkSync, &bsm)
	if err != nil {
		return fmt.Errorf("failed to encode bulk sync message: %v", err)
	}

	nDB.Lock()
	ch := make(chan struct{})
	nDB.bulkSyncAckTbl[node] = ch
	nDB.Unlock()

	err = nDB.memberlist.SendToTCP(&mnode.Node, buf)
	if err != nil {
		nDB.Lock()
		delete(nDB.bulkSyncAckTbl, node)
		nDB.Unlock()

		return fmt.Errorf("failed to send a TCP message during bulk sync: %v", err)
	}

	// Wait on a response only if it is unsolicited.
	if unsolicited {
		startTime := time.Now()
		t := time.NewTimer(30 * time.Second)
		select {
		case <-t.C:
			logrus.Errorf("Bulk sync to node %s timed out", node)
		case <-ch:
			logrus.Debugf("%s: Bulk sync to node %s took %s", nDB.config.NodeName, node, time.Now().Sub(startTime))
		}
		t.Stop()
	}

	return nil
}

// Returns a random offset between 0 and n
func randomOffset(n int) int {
	if n == 0 {
		return 0
	}

	val, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		logrus.Errorf("Failed to get a random offset: %v", err)
		return 0
	}

	return int(val.Int64())
}

// mRandomNodes is used to select up to m random nodes. It is possible
// that less than m nodes are returned.
func (nDB *NetworkDB) mRandomNodes(m int, nodes []string) []string {
	n := len(nodes)
	mNodes := make([]string, 0, m)
OUTER:
	// Probe up to 3*n times, with large n this is not necessary
	// since k << n, but with small n we want search to be
	// exhaustive
	for i := 0; i < 3*n && len(mNodes) < m; i++ {
		// Get random node
		idx := randomOffset(n)
		node := nodes[idx]

		if node == nDB.config.NodeName {
			continue
		}

		// Check if we have this node already
		for j := 0; j < len(mNodes); j++ {
			if node == mNodes[j] {
				continue OUTER
			}
		}

		// Append the node
		mNodes = append(mNodes, node)
	}

	return mNodes
}
