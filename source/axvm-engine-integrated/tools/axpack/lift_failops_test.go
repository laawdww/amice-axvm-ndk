package main
import "testing"
func TestDecodeFailOps(t *testing.T) {
  words := []uint32{0x9E670102, 0xFD000FE0, 0xFD000BE1, 0xFD01B100, 0xFD00B7E0, 0xFD0017E0, 0xFD001FE1, 0x6F00E400, 0x08DFFD09, 0xB8AB790A, 0x9AC9090A, 0x4EA01C01, 0x1E60C000, 0x1E24C000, 0xBD000FE0, 0x9E6703E0}
  for _, w := range words {
    var fp bool
    li, ok := tryDecodeFloatInsn(w, 0, &fp)
    t.Logf("%08X ok=%v fp=%v bc=%x", w, ok, fp, li.bytes)
  }
}
