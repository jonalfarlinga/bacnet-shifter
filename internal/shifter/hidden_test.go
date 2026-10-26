package shifter_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
)

// The Network Port object: the sim has none, so a canned site device on a
// raw socket has one, with the device's addresses in it.
const (
	objectTypeNetworkPort = 56
	propIPAddress         = 400
	propMACAddress        = 423
	cannedInstance        = 7700
)

func cannedSite() *harness.CannedDevice {
	device := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeDevice, InstanceNumber: cannedInstance}
	ai := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogInput, InstanceNumber: 0}
	np := objects.ObjectIdentifier{ObjectType: objectTypeNetworkPort, InstanceNumber: 1}
	return &harness.CannedDevice{Instance: cannedInstance, Objects: map[objects.ObjectIdentifier]map[uint32][]*objects.Object{
		device: {
			uint32(objects.PropertyIdObjectName): {objects.EncString("NP-TEST")},
			uint32(objects.PropertyIdVendorName): {objects.EncString("Canned Controls")},
		},
		ai: {
			uint32(objects.PropertyIdObjectName):   {objects.EncString("NP.ZN.T")},
			uint32(objects.PropertyIdPresentValue): {objects.EncReal(21.5)},
		},
		np: {
			uint32(objects.PropertyIdObjectName): {objects.EncString("NP-1")},
			propIPAddress:                        {objects.EncOctetString([]byte{10, 0, 0, 5})},
			propMACAddress:                       {objects.EncOctetString([]byte{10, 0, 0, 5, 0xBA, 0xC0})},
		},
	}}
}

func unknownObject(err error) bool {
	var be *client.BACnetError
	return errors.As(err, &be) && be.Class == uint32(objects.ErrorClassObject) && be.Code == uint32(control.ErrorCodeUnknownObject)
}

// A Network Port object does not exist on the consumer side: it is left
// out of the object list, a read or subscription naming it is answered
// unknown-object without the site seeing a request for it, and a Who-Has
// for it finds nothing.
func TestHiddenObjects(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.Limited})
	b.AwaitDevices(simDevices, 10*time.Second)
	site := harness.NewRaw(t)
	canned := cannedSite()
	site.ServeDevice(t, canned)
	site.SendIAm(t, b.Shifter.SiteAddr(), cannedInstance)
	heard := b.AwaitDevices(simDevices+1, 10*time.Second)
	dev := deviceByReal(t, b, heard, cannedInstance)
	ctx := b.Ctx()

	list, err := b.Consumer.ReadObjectList(ctx, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0] != deviceObject(dev.Instance) || list[1] != (client.ObjectID{Type: objects.ObjectTypeAnalogInput}) {
		t.Errorf("the object list through the shifter is %v, want the device and the analog input only", list)
	}
	// Element by element too: the count and the elements agree.
	if values, err := b.Consumer.ReadPropertyIndex(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectList, 0); err != nil || len(values) != 1 || values[0].Uint != 2 {
		t.Errorf("object-list[0] is %+v, %v, want 2", values, err)
	}
	if values, err := b.Consumer.ReadPropertyIndex(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectList, 2); err != nil || len(values) != 1 || values[0].Object.Type != objects.ObjectTypeAnalogInput {
		t.Errorf("object-list[2] is %+v, %v, want the analog input", values, err)
	}
	if _, err := b.Consumer.ReadPropertyIndex(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectList, 3); err == nil {
		t.Error("object-list[3] exists on the consumer side")
	}

	np := client.ObjectID{Type: objectTypeNetworkPort, Instance: 1}
	if _, err := b.Consumer.ReadProperty(ctx, dev.Addr, np, propIPAddress); !unknownObject(err) {
		t.Errorf("a read of the Network Port's address: %v, want unknown-object", err)
	}
	results, err := b.Consumer.ReadPropertyMultiple(ctx, dev.Addr, []client.ReadSpec{{Object: np, Props: []uint16{propIPAddress, objects.PropertyIdObjectName}}})
	if err != nil || len(results) != 1 || len(results[0].Props) != 2 || !unknownObject(results[0].Props[0].Err) || !unknownObject(results[0].Props[1].Err) {
		t.Errorf("a ReadPropertyMultiple of the Network Port: %+v, %v, want unknown-object for each property", results, err)
	}
	if _, err := b.Consumer.SubscribeCOV(ctx, dev.Addr, np, client.COVOptions{}, func(client.COVNotification) {}); !unknownObject(err) {
		t.Errorf("a subscription to the Network Port: %v, want unknown-object", err)
	}
	raw := harness.NewRaw(t)
	raw.Send(t, b.Shifter.ConsumerAddr(), plumbing.NewNPDU(false, false, false, false),
		plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoHas, services.WhoHasObjects(objectTypeNetworkPort, 1, "")))
	if rcv := raw.Receive(t, 300*time.Millisecond); rcv != nil {
		t.Errorf("a Who-Has for the Network Port got %+v, want nothing", rcv.APDU)
	}
	for _, obj := range canned.Requests() {
		if obj.ObjectType == objectTypeNetworkPort {
			t.Fatalf("the site saw a request for %s %d", objects.ObjectTypeName(obj.ObjectType), obj.InstanceNumber)
		}
	}
	// And the site's own words never crossed.
	var leak secrets
	for _, s := range []string{"NP-TEST", "NP.ZN.T", "NP-1"} {
		leak.addString(s)
	}
	leak.bytes = append(leak.bytes, []byte{10, 0, 0, 5})
	checkLeak(t, b.ServerRec.Events(), leak)
}

// The strict profile: vendor identifier 0 in the I-Am and in the device
// object, and the version strings replaced; without it they pass.
func TestStrictProfile(t *testing.T) {
	for _, strict := range []bool{false, true} {
		b := harness.Start(t, harness.Options{Configure: func(cfg *shifter.Config) { cfg.Strict = strict }})
		heard := b.AwaitDevices(simDevices, 10*time.Second)
		ahu := deviceByReal(t, b, heard, 1001)
		ctx := b.Ctx()
		vendorID, err := b.Consumer.ReadProperty(ctx, ahu.Addr, deviceObject(ahu.Instance), objects.PropertyIdVendorIdentifier)
		if err != nil || len(vendorID) != 1 {
			t.Fatalf("strict %t: vendor identifier: %+v, %v", strict, vendorID, err)
		}
		vendorName, err := b.Consumer.ReadProperty(ctx, ahu.Addr, deviceObject(ahu.Instance), objects.PropertyIdVendorName)
		if err != nil || len(vendorName) != 1 || vendorName[0].Kind != client.KindString {
			t.Fatalf("strict %t: vendor name: %+v, %v", strict, vendorName, err)
		}
		direct, realDevices := b.Direct()
		real := realDevices[1001]
		directName, err := direct.ReadProperty(ctx, real.Addr, deviceObject(1001), objects.PropertyIdVendorName)
		if err != nil || len(directName) != 1 {
			t.Fatal(err)
		}
		if strict {
			if ahu.VendorID != 0 || vendorID[0].Uint != 0 {
				t.Errorf("strict: the I-Am says vendor %d and the property %d, want 0", ahu.VendorID, vendorID[0].Uint)
			}
			if vendorName[0].Str == directName[0].Str || vendorName[0].Str == "" {
				t.Errorf("strict: the vendor name %q was not replaced", vendorName[0].Str)
			}
		} else {
			if ahu.VendorID != real.VendorID || vendorID[0].Uint != uint64(real.VendorID) {
				t.Errorf("the I-Am says vendor %d and the property %d, want %d", ahu.VendorID, vendorID[0].Uint, real.VendorID)
			}
			if vendorName[0].Str != directName[0].Str {
				t.Errorf("the vendor name %q was replaced outside the strict profile, want %q", vendorName[0].Str, directName[0].Str)
			}
		}
		b.Close()
	}
}
