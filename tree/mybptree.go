package mybptree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"syscall"
)

var (
	err   error
	order = 4
)

const (
	INVALID_OFFSET = 0xdeadbeef
	MAX_FREEBLOCKS = 100
)

var HasExistedKeyError = errors.New("hasExistedKey")
var NotFoundKey = errors.New("notFoundKey")
var InvalidDBFormat = errors.New("invalid db format")

type OFFTYPE uint64

type Tree struct {
	root       OFFTYPE
	nodePool   *sync.Pool
	file       *os.File
	vfile      *os.File
	freeBlocks []OFFTYPE
	blockSize  uint64
	fileSize   uint64
}

type Node struct {
	IsActive bool
	IsLeaf   bool
	Self     OFFTYPE
	Parent   OFFTYPE
	Prev     OFFTYPE
	Next     OFFTYPE
	Children []OFFTYPE
	Keys     [][]byte
	Records  [][]byte
}

func NewTree(filename string) (*Tree, error) {
	var (
		err   error
		fstat os.FileInfo
		stat  syscall.Statfs_t
	)
	t := &Tree{}

	t.root = INVALID_OFFSET
	t.nodePool = &sync.Pool{
		New: func() interface{} {
			return &Node{}
		},
	}
	t.freeBlocks = make([]OFFTYPE, 0, MAX_FREEBLOCKS)
	if t.file, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644); err != nil {
		return nil, err
	}
	//t.vfile to save value when value's position and size as value stored in bptree(t.file)
	if t.vfile, err = os.OpenFile(filename+".db", os.O_CREATE|os.O_RDWR, 0644); err != nil {
		return nil, err
	}

	if err = syscall.Statfs(filename, &stat); err != nil {
		return nil, err
	}
	t.blockSize = uint64(stat.Bsize)
	if t.blockSize == 0 {
		return nil, errors.New("blockSize is zero")
	}

	if fstat, err = t.file.Stat(); err != nil {
		return nil, err
	}
	if _, err := t.vfile.Stat(); err != nil {
		return nil, err
	}

	t.fileSize = uint64(fstat.Size())
	if t.fileSize != 0 {
		if err = t.getBPtreeRootFromExistDBFile(); err != nil {
			return nil, err
		}
		if err = t.checkDiskBlockForFreeNodeList(); err != nil {
			return nil, err
		}
	}

	return t, nil
}

func (t *Tree) Close() error {
	if err := t.vfile.Sync(); err != nil {
		return err
	}
	if err := t.vfile.Close(); err != nil {
		return err
	}

	if err := t.file.Sync(); err != nil {
		return err
	}
	if err := t.file.Close(); err != nil {
		return err
	}
	//if t.vfile != nil {
	//	t.vfile.Sync()
	//	if err := t.vfile.Close(); err != nil {
	//		t.file.Close()
	//		return err
	//	}
	//	if t.file != nil {
	//		t.file.Sync()
	//		return t.file.Close()
	//	}
	//}
	return nil
}

func (t *Tree) getBPtreeRootFromExistDBFile() error {
	node := &Node{}
	for off := uint64(0); off < t.fileSize; off += t.blockSize {
		if err := t.getNode(node, OFFTYPE(off)); err != nil {
			return err
		}
		if node.IsActive {
			break
		}
	}
	if !node.IsActive {
		return InvalidDBFormat
	}
	for node.Parent != INVALID_OFFSET {
		if err := t.getNode(node, node.Parent); err != nil {
			return err
		}
	}
	t.root = node.Self
	return nil
}

func (t *Tree) checkDiskBlockForFreeNodeList() error {
	node := &Node{}
	for off := uint64(0); off < t.fileSize && len(t.freeBlocks) < MAX_FREEBLOCKS; off += t.blockSize {
		if off+t.blockSize > t.fileSize {
			break
		}
		if err := t.getNode(node, OFFTYPE(off)); err != nil {
			return err
		}
		if !node.IsActive {
			t.freeBlocks = append(t.freeBlocks, OFFTYPE(off))
		}
	}
	next_file := ((t.fileSize + t.blockSize - 1) / t.blockSize) * t.blockSize
	for len(t.freeBlocks) < MAX_FREEBLOCKS {
		t.freeBlocks = append(t.freeBlocks, OFFTYPE(next_file))
		next_file += t.blockSize
	}
	t.fileSize = next_file
	return nil
}

func (t *Tree) initNode(node *Node) {
	node.IsActive = true
	node.IsLeaf = false
	node.Self = INVALID_OFFSET
	node.Parent = INVALID_OFFSET
	node.Prev = INVALID_OFFSET
	node.Next = INVALID_OFFSET
	node.Children = nil
	node.Keys = nil
	node.Records = nil
}

func (t *Tree) clearNode(node *Node) {
	node.IsActive = false
	node.IsLeaf = false
	node.Self = INVALID_OFFSET
	node.Parent = INVALID_OFFSET
	node.Prev = INVALID_OFFSET
	node.Next = INVALID_OFFSET
	node.Children = nil
	node.Keys = nil
	node.Records = nil
}

func (t *Tree) getNode(node *Node, offtype OFFTYPE) error {
	if node == nil {
		return fmt.Errorf("cant use nil for getNode")
	}
	t.clearNode(node)
	buf := make([]byte, 8)
	if n, err := t.file.ReadAt(buf, int64(offtype)); err != nil {
		return err
	} else if uint64(n) != 8 {
		return fmt.Errorf("readat %d from %s, expected len = %d but get %d", offtype, t.file.Name(), 4, n)
	}

	bs := bytes.NewBuffer(buf)
	dataLen := uint64(0)
	if err := binary.Read(bs, binary.LittleEndian, &dataLen); err != nil {
		return nil
	}
	if uint64(dataLen)+8 > t.blockSize {
		return fmt.Errorf("flushNode len(node) = %d exceed t.blockSize %d", uint64(dataLen)+4, t.blockSize)
	}

	buf = make([]byte, dataLen)
	if n, err := t.file.ReadAt(buf, int64(offtype)+8); err != nil {
		return err
	} else if uint64(n) != dataLen {
		return fmt.Errorf("readat %d from %s, expected len = %d but get %d", int64(offtype)+4, t.file.Name(), dataLen, n)
	}

	bs = bytes.NewBuffer(buf)

	if err := binary.Read(bs, binary.LittleEndian, &node.IsActive); err != nil {
		return err
	}

	childCount := uint8(0)
	if err := binary.Read(bs, binary.LittleEndian, &childCount); err != nil {
		return nil
	}
	node.Children = make([]OFFTYPE, childCount)
	for i := uint8(0); i < childCount; i++ {
		child := uint64(0)
		if err = binary.Read(bs, binary.LittleEndian, &child); err != nil {
			return err
		}
		node.Children[i] = OFFTYPE(child)
	}

	self := uint64(0)
	if err = binary.Read(bs, binary.LittleEndian, &self); err != nil {
		return nil
	}
	node.Self = OFFTYPE(self)

	next := uint64(0)
	if err = binary.Read(bs, binary.LittleEndian, &next); err != nil {
		return err
	}
	node.Next = OFFTYPE(next)

	prev := uint64(0)
	if err = binary.Read(bs, binary.LittleEndian, &prev); err != nil {
		return err
	}
	node.Prev = OFFTYPE(prev)

	parent := uint64(0)
	if err = binary.Read(bs, binary.LittleEndian, &parent); err != nil {
		return err
	}
	node.Parent = OFFTYPE(parent)

	keyCount := uint8(0)
	if err := binary.Read(bs, binary.LittleEndian, &keyCount); err != nil {
		return err
	}
	node.Keys = make([][]byte, keyCount)
	for i := uint8(0); i < keyCount; i++ {
		l := uint8(0)
		if err := binary.Read(bs, binary.LittleEndian, &l); err != nil {
			return err
		}
		v := make([]byte, l)
		if err := binary.Read(bs, binary.LittleEndian, &v); err != nil {
			return err
		}
		node.Keys[i] = v
	}

	recordCount := uint8(0)
	if err := binary.Read(bs, binary.LittleEndian, &recordCount); err != nil {
		return err
	}
	node.Records = make([][]byte, recordCount)
	for i := uint8(0); i < recordCount; i++ {
		//l := uint8(0)
		//if err := binary.Read(bs, binary.LittleEndian, &l); err != nil {
		//	return err
		//}
		v := make([]byte, 16)
		if err := binary.Read(bs, binary.LittleEndian, &v); err != nil {
			return err
		}
		node.Records[i] = v
	}

	if err = binary.Read(bs, binary.LittleEndian, &node.IsLeaf); err != nil {
		return err
	}

	return nil
}

func (t *Tree) flushNodesAndPutNodesPool(nodes ...*Node) error {
	for _, n := range nodes {
		if err := t.flushNodeAndPutNodePool(n); err != nil {
			return err
		}
	}
	return err
}

func (t *Tree) flushNodeAndPutNodePool(n *Node) error {
	if err := t.flushNode(n); err != nil {
		return err
	}
	t.putNodePool(n)
	return nil
}

func (t *Tree) putNodePool(node *Node) {
	t.nodePool.Put(node)
}

func (t *Tree) flushNode(node *Node) error {
	if node == nil {
		return fmt.Errorf("flushNode == nil")
	}
	if t.file == nil {
		return fmt.Errorf("flush node into disk, but not open file")
	}

	bs := bytes.NewBuffer(make([]byte, 0))
	if err := binary.Write(bs, binary.LittleEndian, node.IsActive); err != nil {
		return err
	}

	childCount := uint8(len(node.Children))
	if err := binary.Write(bs, binary.LittleEndian, childCount); err != nil {
		return err
	}
	for _, v := range node.Children {
		if err := binary.Write(bs, binary.LittleEndian, uint64(v)); err != nil {
			return err
		}
	}

	if err := binary.Write(bs, binary.LittleEndian, uint64(node.Self)); err != nil {
		return err
	}

	if err := binary.Write(bs, binary.LittleEndian, uint64(node.Next)); err != nil {
		return err
	}

	if err := binary.Write(bs, binary.LittleEndian, uint64(node.Prev)); err != nil {
		return err
	}

	if err := binary.Write(bs, binary.LittleEndian, uint64(node.Parent)); err != nil {
		return err
	}

	keyCount := uint8(len(node.Keys))
	if err := binary.Write(bs, binary.LittleEndian, keyCount); err != nil {
		return err
	}
	for _, v := range node.Keys {
		if err := binary.Write(bs, binary.LittleEndian, uint8(len(v))); err != nil {
			return err
		}
		if err := binary.Write(bs, binary.LittleEndian, v); err != nil {
			return err
		}
	}

	recordCount := uint8(len(node.Records))
	if err := binary.Write(bs, binary.LittleEndian, recordCount); err != nil {
		return err
	}
	for _, v := range node.Records {
		//if err := binary.Write(bs, binary.LittleEndian, uint8(len(v))); err != nil {
		//	return err
		//}
		if err := binary.Write(bs, binary.LittleEndian, v); err != nil {
			return err
		}
	}

	if err := binary.Write(bs, binary.LittleEndian, node.IsLeaf); err != nil {
		return err
	}

	dataLen := len(bs.Bytes())
	if uint64(dataLen)+8 > t.blockSize {
		return fmt.Errorf("flushNode len(node) = %d exceed t.blockSize %d", uint64(dataLen)+4, t.blockSize)
	}
	tmpbs := bytes.NewBuffer(make([]byte, 0))
	if err = binary.Write(tmpbs, binary.LittleEndian, uint64(dataLen)); err != nil {
		return err
	}

	data := append(tmpbs.Bytes(), bs.Bytes()...)
	if length, err := t.file.WriteAt(data, int64(node.Self)); err != nil {
		return err
	} else if len(data) != length {
		return fmt.Errorf("writeat %d into %s, expected len = %d but get %d", int64(node.Self), t.file.Name(), len(data), length)
	}

	return nil
}

func (t *Tree) newMappingNodeFromPool(offtype OFFTYPE) (*Node, error) {
	node := t.nodePool.Get().(*Node)
	t.initNode(node)
	if offtype == INVALID_OFFSET {
		return node, nil
	}
	t.clearNode(node)
	if err := t.getNode(node, offtype); err != nil {
		return node, err
	}
	return node, nil
}

func (t *Tree) newNodeFromDisk() (*Node, error) {
	node := t.nodePool.Get().(*Node)
	if len(t.freeBlocks) <= 0 {
		if err := t.checkDiskBlockForFreeNodeList(); err != nil {
			return nil, err
		}
	}
	if len(t.freeBlocks) > 0 {
		off := t.freeBlocks[0]
		t.freeBlocks = t.freeBlocks[1:len(t.freeBlocks)]
		t.initNode(node)
		node.Self = off
		return node, nil
	}
	return nil, fmt.Errorf("can't not alloc more node")
}

func (t *Tree) putFreeBlock(offtype OFFTYPE) {
	if len(t.freeBlocks) >= MAX_FREEBLOCKS {
		return
	}
	t.freeBlocks = append(t.freeBlocks, offtype)
}

func (t *Tree) Find(key []byte) ([]byte, error) {
	var (
		node  *Node
		err   error
		value []byte
	)
	if t.root == INVALID_OFFSET {
		return nil, nil
	}
	if node, err = t.newMappingNodeFromPool(INVALID_OFFSET); err != nil {
		return nil, err
	}
	if err = t.findLeaf(node, key); err != nil {
		return nil, err
	}
	defer t.putNodePool(node)

	for i, nkey := range node.Keys {
		if bytes.Equal(key, nkey) {
			if value, err = t.getValue(node.Records[i]); err != nil {
				return nil, err
			} else {
				return value, nil
			}
		}
	}
	return nil, NotFoundKey
}

func (t *Tree) RangeFind(startKey []byte, endKey []byte) ([][]byte, [][]byte, error) {
	var (
		keys          [][]byte
		position      [][]byte
		node, tmpNode *Node
		err           error
	)
	if node, err = t.newMappingNodeFromPool(INVALID_OFFSET); err != nil {
		return nil, nil, err
	}
	if err = t.findLeaf(node, startKey); err != nil {
		return nil, nil, err
	}
	defer t.putNodePool(node)

	idx1 := sort.Search(len(node.Keys), func(i int) bool {
		return bytes.Compare(startKey, node.Keys[i]) != 1
	})

	idx2 := sort.Search(len(node.Keys), func(i int) bool {
		return bytes.Compare(endKey, node.Keys[i]) == -1
	})
	keys = append(keys, node.Keys[idx1:idx2]...)
	position = append(position, node.Records[idx1:idx2]...)
	if idx2 == len(node.Keys) {
		for node.Next != INVALID_OFFSET {
			if tmpNode, err = t.newMappingNodeFromPool(node.Next); err != nil {
				return nil, nil, err
			}
			idx := sort.Search(len(tmpNode.Keys), func(i int) bool {
				return bytes.Compare(endKey, tmpNode.Keys[i]) == -1
			})
			keys = append(keys, tmpNode.Keys[:idx]...)
			position = append(position, tmpNode.Records[:idx]...)
			*node = *tmpNode
			t.putNodePool(tmpNode)
			if idx != len(tmpNode.Keys) {
				break
			}
		}
	}

	var wg sync.WaitGroup
	var raLock sync.Mutex
	//var err error

	val := make([][]byte, len(keys))
	for i, v := range position {
		wg.Add(1)
		go func(i int, val [][]byte, position []byte) {
			defer wg.Done()
			raLock.Lock()
			val[i], err = t.getValue(position)
			raLock.Unlock()
			if err != nil {
				fmt.Println("read err ", i)
				return
			}
		}(i, val, v)
	}
	wg.Wait()

	return keys, val, nil
}

func (t *Tree) findLeaf(node *Node, key []byte) error {
	var (
		root *Node
		err  error
	)
	rootoff := t.root
	if rootoff == INVALID_OFFSET {
		return nil
	}
	if root, err = t.newMappingNodeFromPool(rootoff); err != nil {
		return err
	}
	defer t.putNodePool(root)
	*node = *root
	for !node.IsLeaf {
		idx := sort.Search(len(node.Keys), func(i int) bool {
			return bytes.Compare(key, node.Keys[i]) != 1
		})
		if idx == len(node.Keys) {
			idx -= 1
		}
		if err = t.getNode(node, node.Children[idx]); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tree) getValue(position []byte) ([]byte, error) {
	var (
		start uint64
		size  uint64
	)
	start = ByteToUint64(position[:8])
	size = ByteToUint64(position[8:])

	value := make([]byte, size)
	if n, err := t.vfile.ReadAt(value, int64(start)); err != nil {
		return nil, err
	} else if uint64(n) != size {
		return nil, fmt.Errorf("readat from %s, expected len = %d but get %d", t.vfile.Name(), size, n)
	}

	return value, nil
}

func Uint64ToByte(x uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, x)
	return b
}

func ByteToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

func (t *Tree) Insert(key, val []byte) error {
	var (
		err    error
		node   *Node
		record []byte
	)
	if t.root == INVALID_OFFSET {
		if record, err = t.setValue(val); err != nil {
			return err
		}
		if node, err = t.newNodeFromDisk(); err != nil {
			return nil
		}
		t.root = node.Self
		node.IsActive = true
		node.Keys = append(node.Keys, key)
		node.Records = append(node.Records, record)
		node.IsLeaf = true
		return t.flushNodeAndPutNodePool(node)
	}
	return t.insertIntoLeaf(key, val)
}

func (t *Tree) setValue(val []byte) ([]byte, error) {
	var (
		start  int64
		size   int
		length int
		err    error
	)
	size = len(val)
	if start, err = t.vfile.Seek(0, 2); err != nil {
		return nil, err
	}
	if length, err = t.vfile.WriteAt(val, start); err != nil {
		return nil, err
	} else if size != length {
		return nil, fmt.Errorf("writeat val into %s, expected len = %d but get %d", t.vfile.Name(), size, length)
	}
	position := Uint64ToByte(uint64(start))
	position = append(position, Uint64ToByte(uint64(size))...)

	return position, nil
}

func (t *Tree) insertIntoLeaf(key, val []byte) error {
	var (
		leaf     *Node
		err      error
		idx      int
		new_leaf *Node
	)
	if leaf, err = t.newMappingNodeFromPool(INVALID_OFFSET); err != nil {
		return nil
	}
	if err = t.findLeaf(leaf, key); err != nil {
		return err
	}

	if idx, err = t.insertKeyValIntoLeaf(leaf, key, val); err != nil {
		return nil
	}
	if err = t.mayUpdatedLastParentKey(leaf, idx); err != nil {
		return err
	}

	if len(leaf.Keys) <= order {
		return t.flushNodesAndPutNodesPool(leaf)
	}

	if new_leaf, err = t.newNodeFromDisk(); err != nil {
		return err
	}

	new_leaf.IsLeaf = true
	if err = t.splitLeafIntoTwoLeaves(leaf, new_leaf); err != nil {
		return err
	}

	if err = t.flushNodesAndPutNodesPool(new_leaf, leaf); err != nil {
		return err
	}

	return t.insertIntoParent(leaf.Parent, leaf.Self, new_leaf.Self, leaf.Keys[len(leaf.Keys)-1])
}

func insertIntoNode(parent *Node, idx int, key []byte, right OFFTYPE) {
	parent.Keys = append(parent.Keys, key)
	for i := len(parent.Keys) - 1; i > idx; i-- {
		parent.Keys[i] = parent.Keys[i-1]
	}
	parent.Keys[idx] = key

	if idx == len(parent.Children) {
		parent.Children = append(parent.Children, right)
		return
	}
	tmpChildren := append([]OFFTYPE{}, parent.Children[idx+1:]...)
	parent.Children = append(append(parent.Children[:idx+1], right), tmpChildren...)
}

func (t *Tree) insertKeyValIntoLeaf(node *Node, key, val []byte) (int, error) {
	var (
		err    error
		record []byte
	)
	idx := sort.Search(len(node.Keys), func(i int) bool {
		return bytes.Compare(key, node.Keys[i]) != 1
	})
	if idx < len(node.Keys) && bytes.Equal(node.Keys[idx], key) {
		return 0, HasExistedKeyError
	}

	if record, err = t.setValue(val); err != nil {
		return 0, err
	}
	node.Keys = append(node.Keys, key)
	node.Records = append(node.Records, record)
	for i := len(node.Keys) - 1; i > idx; i-- {
		node.Keys[i] = node.Keys[i-1]
		node.Records[i] = node.Records[i-1]
	}
	node.Keys[idx] = key
	node.Records[idx] = record
	return idx, nil
}

func (t *Tree) mayUpdatedLastParentKey(node *Node, idx int) error {
	var err error
	if idx == len(node.Keys)-1 && node.Parent != INVALID_OFFSET {
		key := node.Keys[len(node.Keys)-1]
		updataNodeOff := node.Parent
		var (
			updateNode *Node
			n          *Node
		)
		if n, err = t.newMappingNodeFromPool(node.Self); err != nil {
			return err
		}
		*n = *node
		defer t.putNodePool(n)

		for updataNodeOff != INVALID_OFFSET && idx == len(n.Keys)-1 {
			if updateNode, err = t.newMappingNodeFromPool(updataNodeOff); err != nil {
				return err
			}
			for i, v := range updateNode.Children {
				if v == n.Self {
					idx = i
					break
				}
			}
			updateNode.Keys[idx] = key
			if err = t.flushNodeAndPutNodePool(updateNode); err != nil {
				return err
			}
			updataNodeOff = updateNode.Parent
			*n = *updateNode
		}
	}
	return nil
}

func cut(order int) int {
	return (order + 1) / 2
}

func (t *Tree) splitLeafIntoTwoLeaves(leaf, new_leaf *Node) error {
	split := cut(order)

	new_leaf.Keys = append(new_leaf.Keys, leaf.Keys[split:]...)
	new_leaf.Records = append(new_leaf.Records, leaf.Records[split:]...)

	leaf.Keys = leaf.Keys[:split]
	leaf.Records = leaf.Records[:split]

	new_leaf.Next = leaf.Next
	leaf.Next = new_leaf.Self
	new_leaf.Prev = leaf.Self

	new_leaf.Parent = leaf.Parent

	if new_leaf.Next != INVALID_OFFSET {
		var (
			nextnode *Node
			err      error
		)
		if nextnode, err = t.newMappingNodeFromPool(new_leaf.Next); err != nil {
			return nil
		}
		nextnode.Prev = new_leaf.Self
		if err = t.flushNodesAndPutNodesPool(nextnode); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tree) insertIntoNodeAfterSplitting(old_node *Node) error {
	var (
		newNode, child, nextNode *Node
		err                      error
		split                    int
	)
	if newNode, err = t.newNodeFromDisk(); err != nil {
		return err
	}
	split = cut(order)

	for i := split; i <= order; i++ {
		newNode.Keys = append(newNode.Keys, old_node.Keys[i])
		newNode.Children = append(newNode.Children, old_node.Children[i])

		if child, err = t.newMappingNodeFromPool(old_node.Children[i]); err != nil {
			return err
		}
		child.Parent = newNode.Self
		if err = t.flushNodeAndPutNodePool(child); err != nil {
			return err
		}
	}
	newNode.Parent = old_node.Parent

	old_node.Keys = old_node.Keys[:split]
	old_node.Children = old_node.Children[:split]

	newNode.Next = old_node.Next
	old_node.Next = newNode.Self
	newNode.Prev = old_node.Self

	if newNode.Next != INVALID_OFFSET {
		if nextNode, err = t.newMappingNodeFromPool(newNode.Next); err != nil {
			return err
		}
		nextNode.Prev = newNode.Self
		if err = t.flushNodeAndPutNodePool(nextNode); err != nil {
			return err
		}
	}
	if err = t.flushNodesAndPutNodesPool(old_node, newNode); err != nil {
		return err
	}

	return t.insertIntoParent(old_node.Parent, old_node.Self, newNode.Self, old_node.Keys[len(old_node.Keys)-1])
}

func (t *Tree) insertIntoParent(parent, left, right OFFTYPE, key []byte) error {
	var (
		err error
		idx int
		p   *Node
		l   *Node
		r   *Node
	)
	if parent == OFFTYPE(INVALID_OFFSET) {
		if l, err = t.newMappingNodeFromPool(left); err != nil {
			return err
		}
		if r, err = t.newMappingNodeFromPool(right); err != nil {
			return err
		}
		if err = t.newRootNode(l, r); err != nil {
			return err
		}
		return t.flushNodesAndPutNodesPool(l, r)
	}

	if p, err = t.newMappingNodeFromPool(parent); err != nil {
		return err
	}

	idx = sort.Search(len(p.Keys), func(i int) bool {
		return bytes.Compare(key, p.Keys[i]) != 1
	})
	insertIntoNode(p, idx, key, right)

	if len(p.Keys) <= order {
		return t.flushNodeAndPutNodePool(p)
	}

	return t.insertIntoNodeAfterSplitting(p)
}

func (t *Tree) newRootNode(left, right *Node) error {
	var (
		root *Node
		err  error
	)
	if root, err = t.newNodeFromDisk(); err != nil {
		return err
	}
	root.Keys = append(root.Keys, left.Keys[len(left.Keys)-1])
	root.Keys = append(root.Keys, right.Keys[len(right.Keys)-1])
	root.Children = append(root.Children, left.Self)
	root.Children = append(root.Children, right.Self)
	left.Parent = root.Self
	right.Parent = root.Self

	t.root = root.Self
	return t.flushNodeAndPutNodePool(root)
}

func (t *Tree) Update(key []byte, val []byte) error {
	var (
		node   *Node
		record []byte
		err    error
	)

	if t.root == INVALID_OFFSET {
		return NotFoundKey
	}

	if node, err = t.newMappingNodeFromPool(INVALID_OFFSET); err != nil {
		return err
	}

	if err = t.findLeaf(node, key); err != nil {
		return err
	}

	for i, nkey := range node.Keys {
		if bytes.Equal(nkey, key) {
			if record, err = t.setValue(val); err != nil {
				return err
			}
			node.Records[i] = record
			return t.flushNodesAndPutNodesPool(node)
		}
	}
	return NotFoundKey
}

func (t *Tree) Delete(key []byte) error {
	if t.root == INVALID_OFFSET {
		return fmt.Errorf("not found key:%d", key)
	}
	return t.deleteKeyFromLeaf(key)
}

func (t *Tree) deleteKeyFromLeaf(key []byte) error {
	var (
		leaf, nextLeaf, prevLeaf, pprevLeaf *Node
		err                                 error
	)
	if leaf, err = t.newMappingNodeFromPool(INVALID_OFFSET); err != nil {
		return nil
	}
	if err = t.findLeaf(leaf, key); err != nil {
		return err
	}

	idx := sort.Search(len(leaf.Keys), func(i int) bool {
		return bytes.Compare(key, leaf.Keys[i]) != 1
	})
	if idx == len(leaf.Keys) || !bytes.Equal(key, leaf.Keys[idx]) {
		t.putNodePool(leaf)
		return NotFoundKey
	}

	removeKeyFromLeaf(leaf, idx)

	if leaf.Self == t.root {
		return t.flushNodeAndPutNodePool(leaf)
	}

	if idx == len(leaf.Keys) {
		if err = t.mayUpdatedLastParentKey(leaf, idx-1); err != nil {
			return err
		}
	}

	if len(leaf.Keys) >= order/2 {
		return t.flushNodeAndPutNodePool(leaf)
	}

	if leaf.Next != INVALID_OFFSET {
		if nextLeaf, err = t.newMappingNodeFromPool(leaf.Next); err != nil {
			return err
		}

		if nextLeaf.Parent == leaf.Parent {
			if len(nextLeaf.Keys) > order/2 {
				key := nextLeaf.Keys[0]
				val := nextLeaf.Records[0]
				removeKeyFromLeaf(nextLeaf, 0)
				if idx, err = t.insertKeyValIntoLeaf(leaf, key, val); err != nil {
					return err
				}
				if err = t.mayUpdatedLastParentKey(leaf, idx); err != nil {
					return err
				}
				return t.flushNodesAndPutNodesPool(nextLeaf, leaf)
			}
			if leaf.Prev != INVALID_OFFSET {
				if prevLeaf, err = t.newMappingNodeFromPool(leaf.Prev); err != nil {
					return err
				}
				prevLeaf.Next = nextLeaf.Self
				nextLeaf.Prev = prevLeaf.Self
				if err = t.flushNodeAndPutNodePool(prevLeaf); err != nil {
					return err
				}
			} else {
				nextLeaf.Prev = INVALID_OFFSET
			}

			nextLeaf.Keys = append(leaf.Keys, nextLeaf.Keys...)
			nextLeaf.Records = append(leaf.Records, nextLeaf.Records...)

			leaf.IsActive = false
			t.putFreeBlock(leaf.Self)
			if err = t.flushNodesAndPutNodesPool(leaf, nextLeaf); err != nil {
				return err
			}

			return t.deleteKeyFromNode(leaf.Parent, leaf.Keys[len(leaf.Keys)-1])
		} else {
			t.putNodePool(nextLeaf)
		}
	}

	if leaf.Prev != INVALID_OFFSET {
		if prevLeaf, err = t.newMappingNodeFromPool(leaf.Prev); err != nil {
			return err
		}

		if prevLeaf.Parent == leaf.Parent {
			if len(prevLeaf.Keys) > order/2 {
				key := prevLeaf.Keys[len(prevLeaf.Keys)-1]
				val := prevLeaf.Records[len(prevLeaf.Records)-1]
				removeKeyFromLeaf(prevLeaf, len(prevLeaf.Keys)-1)
				if _, err = t.insertKeyValIntoLeaf(leaf, key, val); err != nil {
					return err
				}
				if err = t.mayUpdatedLastParentKey(prevLeaf, len(prevLeaf.Keys)-1); err != nil {
					return err
				}
				return t.flushNodesAndPutNodesPool(prevLeaf, leaf)
			}

			if prevLeaf.Prev != INVALID_OFFSET {
				if pprevLeaf, err = t.newMappingNodeFromPool(prevLeaf.Prev); err != nil {
					return err
				}
				pprevLeaf.Next = leaf.Self
				leaf.Prev = pprevLeaf.Self
				if err = t.flushNodeAndPutNodePool(pprevLeaf); err != nil {
					return err
				}
			} else {
				leaf.Prev = INVALID_OFFSET
			}

			leaf.Keys = append(prevLeaf.Keys, leaf.Keys...)
			leaf.Records = append(prevLeaf.Records, leaf.Records...)

			prevLeaf.IsActive = false
			t.putFreeBlock(prevLeaf.Self)

			if err = t.flushNodesAndPutNodesPool(prevLeaf, leaf); err != nil {
				return err
			}
			return t.deleteKeyFromNode(prevLeaf.Parent, prevLeaf.Keys[len(prevLeaf.Keys)-1])
		} else {
			t.putNodePool(prevLeaf)
		}
	}
	return nil
}

func (t *Tree) deleteKeyFromNode(n OFFTYPE, key []byte) error {
	if n == INVALID_OFFSET {
		return nil
	}
	var (
		node, nextNode, prevNode, pprevNode, newRoot, childNode *Node
		err                                                     error
	)
	if node, err = t.newMappingNodeFromPool(n); err != nil {
		return err
	}

	idx := sort.Search(len(node.Keys), func(i int) bool {
		return bytes.Compare(key, node.Keys[i]) != 1
	})
	removeKeyFromNode(node, idx)

	if idx == len(node.Keys) {
		if err = t.mayUpdatedLastParentKey(node, idx-1); err != nil {
			return err
		}
	}

	if len(node.Keys) >= order/2 {
		return t.flushNodeAndPutNodePool(node)
	}
	if n == t.root && len(node.Keys) == 1 {
		if newRoot, err = t.newMappingNodeFromPool(node.Children[0]); err != nil {
			return err
		}
		node.IsActive = false
		newRoot.Parent = INVALID_OFFSET
		t.root = newRoot.Self
		return t.flushNodesAndPutNodesPool(node, newRoot)
	}

	if node.Next != INVALID_OFFSET {
		if nextNode, err = t.newMappingNodeFromPool(node.Next); err != nil {
			return err
		}
		if nextNode.Parent == node.Parent {
			if len(nextNode.Keys) > order/2 {
				key := nextNode.Keys[0]
				child := nextNode.Children[0]
				if childNode, err = t.newMappingNodeFromPool(child); err != nil {
					return err
				}
				childNode.Parent = node.Self
				removeKeyFromNode(nextNode, 0)
				if idx, err = t.insertKeyValIntoNode(node, key, child); err != nil {
					return err
				}
				if err = t.mayUpdatedLastParentKey(node, idx); err != nil {
					return err
				}
				return t.flushNodesAndPutNodesPool(node, nextNode, childNode)
			}

			if node.Prev != INVALID_OFFSET {
				if prevNode, err = t.newMappingNodeFromPool(node.Prev); err != nil {
					return err
				}
				prevNode.Next = nextNode.Self
				nextNode.Prev = prevNode.Self
				if err = t.flushNodeAndPutNodePool(prevNode); err != nil {
					return err
				}
			} else {
				nextNode.Prev = INVALID_OFFSET
			}

			nextNode.Keys = append(node.Keys, nextNode.Keys...)
			nextNode.Children = append(node.Children, nextNode.Children...)

			for _, v := range node.Children {
				if childNode, err = t.newMappingNodeFromPool(v); err != nil {
					return err
				}
				childNode.Parent = nextNode.Self
				if err = t.flushNodeAndPutNodePool(childNode); err != nil {
					return err
				}
			}

			node.IsActive = false
			t.putFreeBlock(node.Self)
			if err = t.flushNodesAndPutNodesPool(node, nextNode); err != nil {
				return err
			}
			return t.deleteKeyFromNode(node.Parent, node.Keys[len(node.Keys)-1])
		} else {
			t.putNodePool(nextNode)
		}
	}

	if node.Prev != INVALID_OFFSET {
		if prevNode, err = t.newMappingNodeFromPool(node.Prev); err != nil {
			return err
		}

		if prevNode.Parent == node.Parent {
			if len(prevNode.Keys) > order/2 {
				key := prevNode.Keys[len(prevNode.Keys)-1]
				child := prevNode.Children[len(prevNode.Children)-1]
				if childNode, err = t.newMappingNodeFromPool(child); err != nil {
					return err
				}
				childNode.Parent = node.Self
				removeKeyFromNode(prevNode, len(prevNode.Keys)-1)
				if _, err = t.insertKeyValIntoNode(node, key, child); err != nil {
					return err
				}
				if err = t.mayUpdatedLastParentKey(prevNode, len(prevNode.Keys)-1); err != nil {
					return err
				}
				return t.flushNodesAndPutNodesPool(prevNode, node, childNode)
			}

			if prevNode.Prev != INVALID_OFFSET {
				if pprevNode, err = t.newMappingNodeFromPool(prevNode.Prev); err != nil {
					return err
				}
				pprevNode.Next = node.Self
				node.Prev = pprevNode.Self
				if err = t.flushNodeAndPutNodePool(pprevNode); err != nil {
					return err
				}
			} else {
				node.Prev = INVALID_OFFSET
			}

			node.Keys = append(prevNode.Keys, node.Keys...)
			node.Children = append(prevNode.Children, node.Children...)

			// update child's parent
			for _, v := range prevNode.Children {
				if childNode, err = t.newMappingNodeFromPool(v); err != nil {
					return err
				}
				childNode.Parent = node.Self
				if err = t.flushNodesAndPutNodesPool(childNode); err != nil {
					return err
				}
			}
			prevNode.IsActive = false
			t.putFreeBlock(prevNode.Self)

			if err = t.flushNodesAndPutNodesPool(prevNode, node); err != nil {
				return err
			}
			return t.deleteKeyFromNode(prevNode.Parent, prevNode.Keys[len(prevNode.Keys)-1])
		} else {
			t.putNodePool(prevNode)
		}
	}
	return nil
}

func removeKeyFromLeaf(leaf *Node, idx int) {
	leaf.Keys = append(leaf.Keys[:idx], leaf.Keys[idx+1:]...)
	leaf.Records = append(leaf.Records[:idx], leaf.Records[idx+1:]...)
}

func removeKeyFromNode(node *Node, idx int) {
	node.Keys = append(node.Keys[:idx], node.Keys[idx+1:]...)
	node.Children = append(node.Children[:idx], node.Children[idx+1:]...)
}

func (t *Tree) insertKeyValIntoNode(node *Node, key []byte, child OFFTYPE) (int, error) {
	idx := sort.Search(len(node.Keys), func(i int) bool {
		return bytes.Compare(key, node.Keys[i]) != 1
	})
	if idx < len(node.Keys) && bytes.Equal(key, node.Keys[idx]) {
		return 0, HasExistedKeyError
	}
	node.Keys = append(node.Keys, key)
	node.Children = append(node.Children, child)

	for i := len(node.Keys) - 1; i > idx; i-- {
		node.Keys[i] = node.Keys[i-1]
		node.Children[i] = node.Children[i-1]
	}
	node.Keys[idx] = key
	node.Children[idx] = child
	return idx, nil
}

func (t *Tree) ScanTreePrint() error {
	if t.root == INVALID_OFFSET {
		return fmt.Errorf("root = nil")
	}
	Q := make([]OFFTYPE, 0)
	Q = append(Q, t.root)

	floor := 0
	var (
		curNode *Node
		err     error
	)
	for len(Q) != 0 {
		floor++

		l := len(Q)
		fmt.Printf("floor %3d:", floor)
		for i := 0; i < l; i++ {
			if curNode, err = t.newMappingNodeFromPool(Q[i]); err != nil {
				return err
			}
			defer t.putNodePool(curNode)

			// print keys
			if i == l-1 {
				fmt.Printf("%d\n", curNode.Keys)
			} else {
				fmt.Printf("%d, ", curNode.Keys)
			}
			// for _, v := range curNode.Children {
			// 	Q = append(Q, v)
			// }
			Q = append(Q, curNode.Children...)
		}
		Q = Q[l:]
	}
	return nil
}
