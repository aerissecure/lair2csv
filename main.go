package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	lairv1 "github.com/aerissecure/ptfmt2/lairv1"
)

var (
	header []string = []string{"Description", "Rating", "Host", "Port", "Proto"}
)

type row struct {
	description string
	rating      string
	host        string
	port        string
	proto       string
}

func (r *row) csv() []string {
	return []string{r.description, r.rating, r.host, r.port, r.proto}
}

func main() {
	l := log.New(os.Stderr, "", 0)

	file := flag.String("f", "", "lair json file")
	flag.Parse()
	if *file == "" {
		l.Fatalln("-f flag required")
	}

	data, err := ioutil.ReadFile(*file)
	if err != nil {
		l.Fatalf("error reading file: %s", err)
	}

	project := lairv1.Project{}
	if err := json.Unmarshal(data, &project); err != nil {
		log.Fatalf("error parsing JSON: %s", err)
	}

	// fmt.Println(project)

	out, err := os.Create("lair.csv")
	if err != nil {
		log.Fatalf("error creating output file: %s", err)
	}
	defer out.Close()

	writer := csv.NewWriter(out)
	defer writer.Flush()

	if err := writer.Write(header); err != nil {
		log.Fatalf("error writing header to csv file: %s", err)
	}

	for _, v := range project.Vulnerabilities {
		for _, h := range v.Hosts {
			row := []string{
				v.Title,
				fmt.Sprintf("%.1f", v.Cvss),
				h.StringAddr,
				fmt.Sprintf("%d", h.Port),
				h.Protocol,
			}
			if err := writer.Write(row); err != nil {
				log.Fatalf("error writing row to csv file: %s", err)
			}
		}
	}
	fmt.Println("done.")
}
