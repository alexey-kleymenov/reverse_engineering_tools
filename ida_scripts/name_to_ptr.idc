// A simple script to propagate names to their pointers within the selected area
#include <idc.idc>

static main()
{
  auto bitness, select_start, select_end, addr, name;
  bitness = get_inf_attr(INF_LFLAGS) & LFLG_64BIT ? 64 : 32;
  select_start = read_selection_start();
  select_end = read_selection_end();
  for (addr = select_start; addr < select_end; addr = addr + (bitness/8)) {
    if (bitness == 32) {
      name = get_name(dword(addr));
    }
    else if (bitness == 64) {
      name = get_name(qword(addr));
    }
    else {
      print("Unsupported bitness!");
      return;
    }
    set_name(addr, name + "_ptr");
  }
}
