package main
import "testing"
func TestDecodeRealFP(t *testing.T) {
  words := []struct{ w uint32; name string }{
    {0xFD0007E0, "str d0,[sp,#8]"},
    {0xFD4007E0, "ldr d0,[sp,#8]"},
    {0xBD000BE0, "str s0,[sp,#8]"},
    {0x9E670103, "fmov d3,x8"},
    {0x9E660108, "fmov x8,d3"},
    {0x1E602002, "fmov d2,#2"},
    {0xFC410FE0, "ldr d0,[sp,#16]!"},
    {0xFC408400, "ldr d0,[x0],#8"},
    {0xFC018C20, "str d0,[x1,#24]!"},
    {0x1E60C020, "fabs d0,d1"},
  }
  for _, tc := range words {
    var fp bool
    li, ok := tryDecodeFloatInsn(tc.w, 0, &fp)
    if !ok {
      t.Errorf("%s %08X NOT lifted", tc.name, tc.w)
      continue
    }
    t.Logf("%s %08X ok bc=%x", tc.name, tc.w, li.bytes)
  }
}
