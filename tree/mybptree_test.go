package mybptree

import (
	"fmt"
	"strconv"
	"testing"
)

func TestBptree(t *testing.T) {
	var (
		tree *Tree
		err  error
	)
	if tree, err = NewTree("./data.db"); err != nil {
		t.Fatal(err)
	}

	//insert
	// for i := 0; i < 20000; i++ {
	// 	val := "11121212sdlfkhaslfhkasfbakfkawelhuf87348yfhoq7iewhc8oq734fhq478ocqnco7hbo7q84bc784ho7qwehq7f4q378fhcq78whcohq7ihciqehfqiuefhuiqwefhiuqewfhiuqiuefhiuewcnluiaecnualebhuilqweghf74hfiuadcnlakuhuevblnakuvnaliefvnaliuvnuanhichkhmkchulhncskgxhkcuhgksuerhgsuk"
	// 	if err = tree.Insert([]byte(strconv.Itoa(i)), []byte(val)); err != nil {
	// 		t.Fatal(err)
	// 	}
	// }

	// find key
	// for i := 0; i < 20000; i++ {
	// 	if _, err := tree.Find([]byte(strconv.Itoa(i))); err != nil {
	// 		t.Fatal(err)
	// 	}
	// }
	result, _, _ := tree.RangeFind([]byte(strconv.Itoa(0)), []byte(strconv.Itoa(20000)))
	fmt.Println(len(result))
	//defer os.Remove("./data.db")
	defer tree.Close()

}

func Benchmark(b *testing.B) {
	for i := 0; i < b.N; i++ {

	}
}
