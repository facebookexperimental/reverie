/* This control interposes only the formerly registered public root.
 * It cannot synthesize any runtime, constructor record or selector getter. */
static long calls;
void reverie_liteinst_initialize(void) { ++calls; }
long standalone_root_interposer_calls(void) { return calls; }
