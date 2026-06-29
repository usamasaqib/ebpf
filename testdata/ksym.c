#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, uint32_t);
	__type(value, uint64_t);
} array_map __section(".maps");

// Non-weak ksyms must be present in the kernel.
extern void bpf_init __ksym;
// Weak ksyms are potentially zero at runtime.
extern void bpf_trace_run1 __ksym __weak;

__section("socket") int untyped_ksym_test() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = (uint64_t)&bpf_init;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 1;
	val = (uint64_t)&bpf_trace_run1;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	return 0;
}

extern void non_existing_symbol __ksym __weak;

__section("socket") int untyped_ksym_missing_test() {
	if (&non_existing_symbol == 0) {
		return 1;
	}
	return 0;
}

extern const int bpf_prog_active __ksym __weak;

__section("socket") int typed_ksym_test() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = (uint64_t)&bpf_prog_active;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	return 0;
}

extern const struct file_operations__local non_existing_typed_ksym __ksym __weak;

__section("socket") int typed_ksym_missing_test() {
	if (&non_existing_typed_ksym == 0) {
		return 1;
	}
	return 0;
}
