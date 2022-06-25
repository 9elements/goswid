package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/9elements/goswid/pkg/uswid"
	"github.com/CodingVoid/swid"
	"github.com/google/uuid"
)

type FileType int

const (
	JSON FileType = iota
	XML
	CBOR
	USWID
)

var cli struct {
	Debug         bool               `help:"Enable debug mode."`

	GenerateTagID generateTagIDCmd   `cmd help:"generates a 16 byte type-5 SHA1 RFC 4122 UUID (possible use for tag-id)"`
	Print         printCmd           `cmd help:"print swid tag to stdout (in json format)"`
	Convert       convertCmd         `cmd help:"convert between SWID/CoSWID and different file formats (json, xml, cbor, uswid)"`
}

type convertCmd struct {
	ParentFile      string `flag optional short:"p" name:"parent-file" help:"goswid will automatically add a link (with dependency link type) between this file and all other files" type:"existingfile"`
	InputFiles   []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
	OutputFile	 string   `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
	ZlibCompress bool     `flag optional short:"z" name:"zlib-compress" help:"zlib (RFC 1950) compress output, only possible with .uswid file as output" type:"path"`
}

type generateTagIDCmd struct {
	UuidgenName string   `flag required short:"n" name:"name" help:"string to use for uuid generation (e.g. software name)"`
}

type printCmd struct {
	ParentFile      string `flag optional short:"p" name:"parent-file" help:"goswid will automatically add a link (with dependency link type) between this file and all other files" type:"existingfile"`
	InputFiles []string `arg required name:"input-file-paths" help:"Paths to imput files." type:"existingfile"`
}

func (c *convertCmd) Run() error {
	var utag uswid.UswidSoftwareIdentity
	for _, input_file_path := range c.InputFiles {
		if err := utag.FromFile(input_file_path); err != nil {
			return err
		}
	}

	// if there is a topfile specified, we create a link between that CoSWID tag and all others
	if c.ParentFile != "" {
		var parent_tag uswid.UswidSoftwareIdentity
		parent_tag.FromFile(c.ParentFile)
		if len(parent_tag.Identities) > 1 {
			return errors.New("Top tag should only be a single CoSWID tag")
		}
		stag := parent_tag.Identities[0]
		for _, id := range utag.Identities {
			link, err := swid.NewLink(id.TagID.URI(), *swid.NewRel(swid.RelRequires))
			if err != nil {
				return err
			}
			if err := stag.AddLink(*link); err != nil {
				return err
			}
		}
		utag.Identities = append(utag.Identities, stag)
	}

	// check file extension and put CoSWID tags into output file
	var err error
	var output_buf []byte
	of_parts := strings.Split(c.OutputFile, ".")
	if len(of_parts) < 2 {
		return errors.New("no file extension found")
	}
	switch of_parts[len(of_parts)-1] {
	case "json":
		output_buf, err = utag.ToJSON()
	case "xml":
		output_buf, err = utag.ToXML()
	case "cbor":
		output_buf, err = utag.ToUSWID(c.ZlibCompress)
	case "uswid":
		output_buf, err = utag.ToCBOR(c.ZlibCompress)
	default:
		return errors.New("output file extension not supported")
	}
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(c.OutputFile, output_buf, 0644); err != nil {
		return err
	}
	return nil
}

func (p *printCmd) Run() error {
	var utag uswid.UswidSoftwareIdentity
	for _, input_file_path := range p.InputFiles {
		if err := utag.FromFile(input_file_path); err != nil {
			return err
		}
	}

	// if there is a topfile specified, we create a link between that CoSWID tag and all others
	if p.ParentFile != "" {
		var parent_tag uswid.UswidSoftwareIdentity
		parent_tag.FromFile(p.ParentFile)
		if len(parent_tag.Identities) > 1 {
			return errors.New("Top tag should only be a single CoSWID tag")
		}
		stag := parent_tag.Identities[0]
		for _, id := range utag.Identities {
			link, err := swid.NewLink(id.TagID.URI(), *swid.NewRel(swid.RelRequires))
			if err != nil {
				return err
			}
			if err := stag.AddLink(*link); err != nil {
				return err
			}
		}
		utag.Identities = append(utag.Identities, stag)
	}
	output_buf, err := utag.ToJSON()
	if err != nil {
		return fmt.Errorf("uswid_input_tag.ToJSON(): %w", err)
	}
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(output_buf), "", "    "); err != nil {
		return err
	}

	fmt.Println(prettyJSON.String())
	return nil
}

func (g *generateTagIDCmd) Run() error {
	fmt.Println(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(g.UuidgenName)))
	return nil
}
