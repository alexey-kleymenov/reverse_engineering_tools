/*
  This script attempts to intercept the moment when each API is dynamically resolved to write down its address somewhere.
  Change the relative addresses according to your needs.
  Tested on BlackMatter ransomware sample 706f3eec328e91ff7f66c8f0a2fb9b556325c153a329a2062dc85879c540839d

  WARNING! This script will execute the analyzed file so use it at your own risk, always in an isolated environment!
*/
#import <idc.idc>

static main() {
  auto ep_addr, base_addr, api_addr, i, status, stop_addr, resolved_api_addr, write_api_addr, antire_addr;
  // stop at the entry point (fix the ordinal number if your sample has multiple entries)
  ep_addr = get_entry(get_entry_ordinal(0));
  add_bpt(ep_addr, 1);
  start_process("", "", "");
  wait_for_next_event(WFNE_SUSP, -1);

  base_addr = get_first_module();
  // put a breakpoint where all APIs are resolved
  stop_addr = base_addr + 0x11583;
  add_bpt(stop_addr, 1);
  // put a breakpoint where each API is resolved
  resolved_api_addr = base_addr + 0x7927;
  add_bpt(resolved_api_addr, 1);
  // put a breakpoint where the address for the API is ready to be written
  write_api_addr = base_addr + 0x7a27;
  add_bpt(write_api_addr, 1);
  // bypass anti-debugging trick
  antire_addr = base_addr + 0x7941;
  patch_byte(antire_addr, 0x75);
  
  for (i=0;i<500;i=i+1) {
    run_to(stop_addr);
    status = wait_for_next_event(WFNE_SUSP, -1);
    if (status == BREAKPOINT && get_reg_value("EIP") == resolved_api_addr) {
      api_addr = get_reg_value("EAX");
      run_to(stop_addr);
      status = wait_for_next_event(WFNE_SUSP, -1);
      if (status == BREAKPOINT && get_reg_value("EIP") == write_api_addr) {
        msg("%x\n", get_reg_value("EDI")-4);
        patch_dword(get_reg_value("EDI")-4, api_addr);
      }
    }
    if (status == BREAKPOINT && get_reg_value("EIP") == stop_addr) {
      break;
    }
  }
  msg("Done!\n");
}
