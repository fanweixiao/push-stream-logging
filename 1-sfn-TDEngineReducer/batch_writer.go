package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yomorun/yomo/rx"
)

// StreamLogEntity represents the structure of data
type StreamLogEntity struct {
	From    string `json:"from"`    // source IP address
	Packets int    `json:"packets"` // udp packets
}

func store(arr []StreamLogEntity) error {
	// db, err := sql.Open("taosSql", "root:taosdata@/tcp(localhost:6030)/yomo")
	// if err != nil {
	// 	fmt.Printf("Open database error: %s\n", err)
	// }
	// defer db.Close()

	// // Ensure 'streamlogger' table exists
	// sql := "CREATE TABLE IF NOT EXISTS streamlogger (ts TIMESTAMP, v FLOAT)"
	// _, err = db.Exec(sql)
	// if err != nil {
	// 	fmt.Printf("db.Exec error: %s\n", err)
	// }

	// ***Batch insert***
	// https://www.taosdata.com/docs/cn/v2.0/insert
	// TDengine 支持一次写入多条记录，比如下面这条命令就将两条记录写入到表 d1001 中：
	// INSERT INTO d1001 VALUES (1538548684000, 10.2, 220, 0.23) (1538548696650, 10.3, 218, 0.25);
	var sqlStr string
	for _, statements := range arr {
		sqlStr += fmt.Sprintf("(\"%s\", %d)", statements.From, statements.Packets)
	}
	sql := "INSERT INTO streamlogger VALUES " + sqlStr
	fmt.Println(sql)

	// _, err = db.Exec(sql)
	// if err != nil {
	// 	fmt.Printf("Insert error: %s\n", err)
	// }

	return nil
}

// batch write to db
var echo = func(_ context.Context, i interface{}) (interface{}, error) {
	var items = []StreamLogEntity{}
	if values, ok := i.([]interface{}); ok {
		for _, val := range values {
			l := val.(*StreamLogEntity)
			items = append(items, *l)
		}
	}
	store(items)
	return nil, nil
}

// Handler will handle data in Rx way
func Handler(rxstream rx.Stream) rx.Stream {
	stream := rxstream.
		Unmarshal(json.Unmarshal, func() interface{} { return &StreamLogEntity{} }).
		BufferWithCount(50).
		Map(echo).
		StdOut()

	return stream
}

func DataTags() []byte {
	return []byte{0x33}
}
