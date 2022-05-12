package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/9elements/goswid/pkg/uswid"
	"github.com/google/uuid"
)

type FileType int

const (
	JSON FileType = iota
	XML
	CBOR
	USWID
)

var output_file_path *string = flag.String("o", "", "output file, either .json .xml .cbor or .uswid file")
var compressZlib *bool = flag.Bool("z", false, "zlib (RFC 1950) compress output, only possible with .uswid file as output")
var tag_uuidgen_name *string = flag.String("t", "", "generates a 16 byte type-5 SHA1 RFC 4122 UUID (possible use for tag-id)")

func ErrorOut(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	os.Exit(-1)
}

func main() {
	flag.Parse()
	if len(*tag_uuidgen_name) > 0 {
		tag_uuid := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(*tag_uuidgen_name))
		fmt.Println(tag_uuid)
		os.Exit(0)
	}
	input_file_paths := flag.Args()
	var err error
	of_len := len(*output_file_path)
	if of_len == 0 {
		ErrorOut("no output file specfied\n")
	}
	if len(input_file_paths) < 1 {
		ErrorOut("no input files specified\n")
	}

	/* check file extension of output file */
	var output_format FileType
	of_parts := strings.Split(*output_file_path, ".")
	if len(of_parts) < 2 {
		ErrorOut("no file extensions found\n")
	}
	switch of_parts[len(of_parts)-1] {
	case "json":
		output_format = JSON
	case "xml":
		output_format = XML
	case "cbor":
		output_format = CBOR
	case "uswid":
		output_format = USWID
	default:
		ErrorOut("output file extension not supported\n")
	}

	var uswid_input_tag uswid.UswidSoftwareIdentity
	for _, input_file_path := range input_file_paths {
		input_file, err := ioutil.ReadFile(input_file_path)
		if err != nil {
			ErrorOut("%s\n", err)
		}

		/* check file extension of input file */
		if_parts := strings.Split(input_file_path, ".")
		switch if_parts[len(if_parts)-1] {
		case "json":
			err = uswid_input_tag.FromJSON(input_file)
		case "xml":
			err = uswid_input_tag.FromXML(input_file)
		case "cbor":
			err = uswid_input_tag.FromCBOR(input_file, false)
		case "uswid":
			fallthrough
		default:
			_, err = uswid_input_tag.FromUSWID(input_file)
		}
		if err != nil {
			ErrorOut("%s\n", err)
		}
	}
	var output_buf []byte
	switch output_format {
	case JSON:
		output_buf, err = uswid_input_tag.ToJSON()
	case XML:
		output_buf, err = uswid_input_tag.ToXML()
	case USWID:
		output_buf, err = uswid_input_tag.ToUSWID(*compressZlib)
	case CBOR:
		output_buf, err = uswid_input_tag.ToCBOR(*compressZlib)
	}
	if err != nil {
		ErrorOut("%s\n", err)
	}

	if err := ioutil.WriteFile(*output_file_path, output_buf, 0644); err != nil {
		ErrorOut("%s\n", err)
	}
}
