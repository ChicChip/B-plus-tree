package main

import (
	"fmt"
	mybptree "mybptree/tree"
	"time"
)

var (
	bptree *mybptree.Tree
)

func main() {
	// var (
	// 	tree *mybptree.Tree
	// 	err  error
	// )
	// if tree, err = mybptree.NewTree("./data.db"); err != nil {
	// 	fmt.Println("19")
	// }

	// //for i := 0; i < 20000; i++ {
	// //	val := "11121212sdlfkhaslfhkasfbakfkawelhuf87348yfhoq7iewhc8oq734fhq478ocqnco7hbo7q84bc784ho7qwehq7f4q378fhcq78whcohq7ihciqehfqiuefhuiqwefhiuqewfhiuqiuefhiuewcnluiaecnualebhuilqweghf74hfiuadcnlakuhuevblnakuvnaliefvnaliuvnuanhichkhmkchulhncskgxhkcuhgksuerhgsuk"
	// //	if err = tree.Insert([]byte(strconv.Itoa(i)), []byte(val)); err != nil {
	// //		fmt.Println("e")
	// //	}
	// //}
	// //for i := 0; i < 20; i++ {
	// //	val := fmt.Sprintf("%d", i)
	// //	if err = tree.Insert([]byte(strconv.Itoa(i)), []byte(val)); err != nil {
	// //		fmt.Println(err)
	// //	}
	// //}
	// //tree.ScanTreePrint()
	// // find key
	// //
	// result, _, _ := tree.RangeFind([]byte(strconv.Itoa(0)), []byte(strconv.Itoa(9)))
	// fmt.Println(len(result))
	// FilterArgs := [...]uint32{1, 3, 0, 200}
	// args1 := int(math.Pow(-1, float64(FilterArgs[0]))) * int(FilterArgs[1])
	// args2 := int(math.Pow(-1, float64(FilterArgs[2]))) * int(FilterArgs[3])
	// date1 := time.Now().AddDate(0, 0, args1)
	// date2 := time.Now().AddDate(0, 0, args2+1)
	// p1, _ := strconv.ParseUint(fmt.Sprintf("%d%02d%02d", date1.Year(), date1.Month(), date1.Day()), 10, 32)
	// p2, _ := strconv.ParseUint(fmt.Sprintf("%d%02d%02d", date2.Year(), date2.Month(), date2.Day()), 10, 32)
	// fmt.Printf("%d,%d\n", uint32(p1), uint32(p2))

	// args := fmt.Sprintf("%%\"filter_tag_id\": %d%%", 13)
	// fmt.Println(args)
	
	fmt.Println(seconds)

}
