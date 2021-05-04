package rmf

import "encoding/xml"

//Structs based on checklist DOM
type Checklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   Asset    `xml:"ASSET"`
	Stigs   Stigs    `xml:"STIGS"`
}

type Asset struct {
	XMLName   xml.Name `xml:"ASSET"`
	Role      string   `xml:"ROLE"`
	AssetType string   `xml:"ASSET_TYPE"`
	Hostname  string   `xml:"HOST_NAME"`
	HostIP    string   `xml:"HOST_IP"`
	HostMac   string   `xml:"HOST_MAC"`
	HostFQDN  string   `xml:"HOST_FQDN"`
	TechArea  string   `xml:"TECH_AREA"`
	TargetKey string   `xml:"TARGET_KEY"`
	WebOrDB   string   `xml:"WEB_OR_DATABASE"`
	WebDBSite string   `xml:"WEB_DB_SITE"`
	WebDBInst string   `xml:"WEB_DB_INSTANCE"`
}

type Stigs struct {
	XMLName xml.Name `xml:"STIGS"`
	Istig   Istig    `xml:"iSTIG"`
}

type Istig struct {
	XMLName  xml.Name `xml:"iSTIG"`
	StigInfo StigInfo `xml:"STIG_INFO"`
}

type StigInfo struct {
	XMLName xml.Name `xml:"STIG_INFO"`
	SiData  []SiData `xml:"SI_DATA"`
}

type SiData struct {
	XMLName xml.Name `xml:"SI_DATA"`
	SidName string   `xml:"SID_NAME"`
	SidData string   `xml:"SID_DATA"`
}
