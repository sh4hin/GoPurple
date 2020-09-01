package helpers

import (
	"io/ioutil"
	"log"
	"net/http"
)


func FetchUrl(url string) []byte {
    res, err := http.Get(url)

	if err != nil {
		log.Fatal(err)
	}
	data, _ := ioutil.ReadAll(res.Body)

	_ = res.Body.Close()

	return data
}

