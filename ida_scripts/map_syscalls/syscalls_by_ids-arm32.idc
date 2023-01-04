// This script searches for 32-bit ARM syscalls by their IDs and adds their human-readable names to the IDA database in the form of Names.
// The mapping table for syscalls needs to be provided separately in the TSV format, in this case in the syscall_table-arm32.tsv file (from https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm-32_bit_EABI)
// Tested on a89ad47d1862813c11d382aafe84a19dc9e79171ba8b688ef81721bb163ba652 sample
#include <idc.idc>

static read_matches(file_path) {
  auto f, line, matches, first_tab_ind, second_tab_ind, second_part, syscall_int, syscall_name;
  f = fopen(file_path, "r");
  if (f == 0) {
    warning("No file to read the matches from!\n");
    return;
  }
  line = readstr(f);
  matches = create_array("matches");
  if (matches == -1) {
    matches = get_array_id("matches");
  }
  while (line != -1) {
    first_tab_ind = strstr(line, "\t");
    if (first_tab_ind == -1) {
      warning("Wrong match file format\n");
      return;
    }
    syscall_int = substr(line, 0, first_tab_ind);
    second_part = substr(line, first_tab_ind + 1, -1);
    second_tab_ind = strstr(second_part, "\t");
    if (second_tab_ind == -1) {
      warning("Wrong match file format\n");
      return;
    }
    syscall_name = substr(second_part, 0, second_tab_ind);
    set_hash_string(matches, syscall_int, syscall_name);
    line = readstr(f);
  }
  fclose(f);
  return matches;
}

static main() {
  auto ea, i, temp_ea, inst, operand0, operand1, match, matches, syscall_id, syscall_name;
  matches = read_matches("c:\\syscall_table-arm32.tsv");
  ea = get_inf_attr(INF_MIN_EA);
  while ((ea=find_text(ea, SEARCH_DOWN, 0, 0, "SVC")) != BADADDR) {
    temp_ea = ea;
    for (i=0; i<5; i=i+1) {
      temp_ea = prev_head(temp_ea, 0);
      if (is_code(get_flags(temp_ea)) == 0) {
        break;
      }
      inst = print_insn_mnem(temp_ea);
      if (inst == "MOV") {
        operand0 = get_operand_value(temp_ea, 0);
        // R7 on 32-bit ARM
        if (operand0 == 7) {
          syscall_id = ltoa(get_operand_value(temp_ea, 1), 10);
          syscall_name = get_hash_string(matches, syscall_id);
          if (syscall_name != "") {
            msg("%x: %s\n", temp_ea, syscall_name);
            set_name(ea, syscall_name, SN_NOCHECK|SN_FORCE);
            break;
          }
        }
      }
    }
    ea = next_head(ea, BADADDR);
  }
  msg("Done!\n");
}
