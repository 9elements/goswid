package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/9elements/goswid/pkg/uswid"
	"github.com/veraison/swid"
)


type FileType int
const (
	JSON FileType = iota
	XML
	CBOR
	USWID
)

var output_file_path *string = flag.String("o", "", "output file")
var compress *bool = flag.Bool("c", false, "compress output, only possible with uswid file output extension")

func ErrorOut(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	os.Exit(-1)
}

func main() {
	flag.Parse()
	input_file_paths := flag.Args()
	var err error
	of_len := len(*output_file_path)
	if of_len == 0 {
		ErrorOut("no output file specfied")
	}
	if len(input_file_paths) < 1 {
		ErrorOut("no input files specified\n")
	}

	var output_format FileType
	if of_len >= 5 && (*output_file_path)[of_len-5:of_len] == ".json" {
		output_format = JSON
	} else if of_len >= 4 && (*output_file_path)[of_len-4:of_len] == ".xml" {
		output_format = XML
	} else if of_len >= 5 && (*output_file_path)[of_len-5:of_len] == ".cbor" {
		output_format = CBOR
	} else if of_len >= 6 && (*output_file_path)[of_len-6:of_len] == ".uswid" {
		output_format = USWID
	} else {
		ErrorOut("output file extension not supported\n")
	}
	//if (output_format != uswid) && (len(input_file_paths) > 1) {
	//	ErrorOut("multiple input files are only supported in conjunction with the .uswid output file extension\n")
	//}

	var uswid_input_tag uswid.UswidSoftwareIdentity
	for _, input_file_path := range input_file_paths {
		input_file, err := ioutil.ReadFile(input_file_path)
		if err != nil {
			ErrorOut("%s\n", err)
		}

		if_len := len(input_file_path)
		isUSWID := false
		var input_tag swid.SoftwareIdentity
		if if_len >= 5 && input_file_path[if_len-5:if_len] == ".json" {
			err = input_tag.FromJSON(input_file)
		} else if if_len >= 4 && input_file_path[if_len-4:if_len] == ".xml" {
			err = input_tag.FromXML(input_file)
		} else if if_len >= 5 && input_file_path[if_len-5:if_len] == ".cbor" {
			err = input_tag.FromCBOR(input_file)
		} else if if_len >= 6 && input_file_path[if_len-6:if_len] == ".uswid" {
			_, err = uswid_input_tag.FromUSWID(input_file)
			isUSWID = true
		} else {
			fmt.Printf("input file extension not recognized, assuming USWID: %s\n", input_file_path)
			_, err = uswid_input_tag.FromUSWID(input_file)
			isUSWID = true
		}
		if err != nil {
			ErrorOut("%s\n", err)
		}
		if !isUSWID {
			uswid_input_tag.Identities = append(uswid_input_tag.Identities, input_tag)
		}
	}
	var output_buf []byte
	switch output_format {
		case JSON:
			output_buf, err = uswid_input_tag.ToJSON()
		case XML:
			output_buf, err = uswid_input_tag.ToXML()
		case USWID:
			output_buf, err = uswid_input_tag.ToUSWID(*compress)
		case CBOR:
			output_buf, err = uswid_input_tag.ToCBOR()
	}
	if err != nil {
		ErrorOut("%s\n", err)
	}

	if err := ioutil.WriteFile(*output_file_path, output_buf, 0644); err != nil {
		ErrorOut("%s\n", err)
	}
}
