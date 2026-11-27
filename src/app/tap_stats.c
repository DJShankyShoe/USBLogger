/*
 * What the tap prints about itself: the banner, the stats block (key s, and every 10 s), the profile and
 * load lines, and stack use. Part of USBLogger.c (#included).
 */

static usb_selftest_bench_t g_bench;   /* the boot-time decode benchmark */

/* Prints the banner: the self-test, boot timing, the card and its check, and the rest of what the boot found. */
static void print_banner(void)
{
    tap_printf("\n");
    tap_printf("[self]  decode/parse/log self-test: %s (run at boot, before capture started)\n",
           g_selftest_pass ? "PASS" : "FAIL");
    tap_printf("[boot]  capture started %.0f ms after power-up; the wireless chip (LED) then took %.0f ms to"
           " start; terminal connected at %.1f s\n",
           (double)g_boot_capture_us / 1000.0, (double)g_boot_cyw43_us / 1000.0,
           (double)time_us_64() / 1e6);
    if (g_card_check_ran) {
        tap_printf("[check] the card's log before this session: %llu sessions, %llu records (%llu never reached"
               " SESSION_END: power lost), %lu blocks read in %.1f s -- %s\n",
               (unsigned long long)g_card_check.sessions, (unsigned long long)g_card_check.records,
               (unsigned long long)g_card_check.unfinished, (unsigned long)g_card_check_blocks,
               (double)g_card_check_us / 1e6,
               g_card_check_ok ? "every chain re-derives: PASS" : "FAIL");
        if (g_card_check.broken || !g_card_check_walked) {
            tap_printf("[check] %s, in session %016llx at seq %llu. Nothing is written to the card this session.\n",
                   g_card_check.why ? g_card_check.why : "a block could not be read back",
                   (unsigned long long)g_card_check.broken_session,
                   (unsigned long long)g_card_check.broken_seq);
        }
        if (g_card_check_aux & AUDIT_CHECKPOINT_NONE) {
            tap_printf("[check] checkpoint: none in this Pico's flash yet (first use); one is kept when this session"
                   " ends\n");
        } else if (g_card_check_aux & AUDIT_CHECKPOINT_LOST) {
            tap_printf("[check] checkpoint: FAIL -- %s. Nothing is written to the card this session. If that is"
                   " expected (a card you formatted on purpose), press c to accept the card as it is: kept as"
                   " the new reference when the session ends (q), effective from the next boot. A new card"
                   " can also be accepted with its card_password.txt.\n", g_ckpt_why);
        } else {
            tap_printf("[check] checkpoint: the card still holds the last record this tap wrote (session %016llx"
                   " seq %llu)%s\n", (unsigned long long)g_ckpt.session_id, (unsigned long long)g_ckpt.seq,
                   (g_card_check_aux & AUDIT_CHECKPOINT_PASSWORD) ? " -- set by an accept with card_password.txt"
                   : (g_card_check_aux & AUDIT_CHECKPOINT_ACCEPTED) ? " -- set by an operator's accept" : "");
        }
        if (g_card_full) {
            tap_printf("[check] the card's log is FULL (%lu blocks left%s%s): the drive stays off. Copy the log off"
                       " the card, delete it, and give the card a card_password.txt\n",
                       (unsigned long)sd_log_blocks_free(&g_sd_log), g_sd_info.grow_why ? "; " : "",
                       g_sd_info.grow_why ? g_sd_info.grow_why : "");
        }
        if (g_accept_why != NULL) {
            tap_printf("[check] %s; the file %s\n", g_accept_why,
                       g_sd_info.password_removed ? "was wiped and deleted"
                                              : "is STILL ON THE CARD (read-only?): delete it on a PC");
        }
    } else {
        tap_printf("[check] the card's log was NOT checked: no usable card\n");
    }
    {
        char genesis[65];
        static const char digits[] = "0123456789abcdef";
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            genesis[2 * i]     = digits[g_log.genesis[i] >> 4];
            genesis[2 * i + 1] = digits[g_log.genesis[i] & 0x0Fu];
        }
        genesis[64] = '\0';
        /* tests/console_log.py reads the genesis from this line. */
        tap_printf("[chain] HMAC-SHA256, key id %08lx; session %016llx follows genesis %s\n",
               (unsigned long)audit_key_id(&g_chain_key), (unsigned long long)g_log.session_id, genesis);
    }
    tap_printf("[model] %s\n", g_model_boot_note);
    print_vbus_stats();
    tap_printf("[relay] GPIO %u (pin 27): drive power %s%s\n", (unsigned)RELAY_PIN, g_drive_power ? "ON" : "OFF",
           g_drive_power ? ""
           : !g_selftest_pass ? " -- the self-test FAILED; key 1 powers it anyway (logged)"
           : g_card_full      ? " -- the card's log is full (fail-closed): nothing more could be logged"
                              : " -- the card's log did not pass its check (fail-closed); key 1 powers it anyway"
                                " (logged)");
    if (g_sd_info.ok) {
        tap_printf("[sd]    card %.2f GB, SPI %.1f MHz: %s; opened in %lu ms (start-ups %lu); blocks written"
               " encrypted (ChaCha20)\n",
               (double)g_sd_info.sectors * 512.0 / 1e9, (double)g_sd_info.spi_hz / 1e6, g_sd_info.why,
               (unsigned long)g_sd_info.open_ms, (unsigned long)g_sd_info.init_tries);
    } else {
        tap_printf("[sd]    card NOT in use: %s (after %lu ms, %lu start-ups). Records go to the console only,"
               " and each one is counted as an sd failure\n", g_sd_info.why, (unsigned long)g_sd_info.open_ms,
               (unsigned long)g_sd_info.init_tries);
    }
#if TAP_MEASURE
    /* The same code and input every boot: cycles that move between boots mean the chip counts the
     * same work differently. */
    tap_printf("[bench] fixed %lu-packet WRITE stream (%lu words), core1's decoder code run on core0:"
           " %lu cycles per file-data packet (min of %u; runs %lu %lu %lu %lu %lu)%s\n",
           (unsigned long)BENCH_TRANSACTIONS, (unsigned long)g_bench.words,
           (unsigned long)(g_bench.min_cycles / BENCH_TRANSACTIONS), (unsigned)BENCH_RUNS,
           (unsigned long)g_bench.runs[0], (unsigned long)g_bench.runs[1], (unsigned long)g_bench.runs[2],
           (unsigned long)g_bench.runs[3], (unsigned long)g_bench.runs[4],
           g_bench.ok ? "" : " -- FAILED: not decoded as expected, figures invalid");
#endif
    {
        const uint32_t d0 = (g_qmi_timing_boot & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
        const uint32_t d1 = (g_qmi_timing_run & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
        const uint32_t r0 = (g_qmi_timing_boot & QMI_M0_TIMING_RXDELAY_BITS) >> QMI_M0_TIMING_RXDELAY_LSB;
        const uint32_t r1 = (g_qmi_timing_run & QMI_M0_TIMING_RXDELAY_BITS) >> QMI_M0_TIMING_RXDELAY_LSB;
        const double hz = (double)clock_get_hz(clk_sys);
        tap_printf("[clock] %.0f MHz, core %.2f V; flash interface CLKDIV %lu -> %lu (flash clock %.0f MHz),"
               " RXDELAY %lu -> %lu half cycles (%.2f ns)\n",
               hz / 1e6, 0.55 + 0.05 * (double)vreg_get_voltage(), (unsigned long)d0, (unsigned long)d1,
               d1 ? hz / (double)d1 / 1e6 : 0.0, (unsigned long)r0, (unsigned long)r1,
               (double)r1 * 1e9 / (2.0 * hz));
    }
    tap_printf("=== Forensic USB Audit Tap -- Phase 1 (USB 1.1 passive capture) ===\n");
    tap_printf("tap pins: D+=GPIO%d D-=GPIO%d (inputs only, bus is never driven)\n",
           TAP_DP_PIN, TAP_DM_PIN);
    tap_printf("sys clock: %lu kHz   sample rate: %.3f MHz (%ux oversample, %s)\n",
           (unsigned long)(clock_get_hz(clk_sys) / 1000u),
           (double)(g_capture.sample_hz / 1e6f),
           (unsigned)g_capture.oversample,
           usb_speed_name(g_capture.speed));
    tap_printf("log format: AUD|seq|ts_ns|type|op|opcode|lba|blocks|len|residue|"
           "dev|ep|lun|tag|status|flags|sha256|op_number|session_id|aux|reserved\n");
    tap_printf("keys: s=stats  p=recent packets  h=chain head  r=raw samples  "
           "0/1=drive power off/on  c=accept the card  q=end session\n\n");
}

/* Where core1's cycles went, per path (the measure build). */
#if USB_PROFILE
/* Prints one longest-iteration record: its length, its bus time and its parts in cycles. */
static void print_iter(const char *what, const iter_max_t *m)
{
    if (m->cyc == 0u) {
        return;
    }
    const double cyc_per_ms = (double)clock_get_hz(clk_sys) / 1000.0;
    const uint32_t parts = m->poll + m->run + m->flush;
    tap_printf("%s: %.2f ms, pass from bus time %.3f s: poll %lu, decode %lu over %lu words"
           " (%lu SE1 samples), flush %lu, rest %lu cycles\n",
           what, (double)m->cyc / cyc_per_ms,
           (double)usb_capture_sample_to_ns(&g_capture, m->at) / 1e9,
           (unsigned long)m->poll, (unsigned long)m->run, (unsigned long)m->words,
           (unsigned long)m->se1, (unsigned long)m->flush,
           (unsigned long)(m->cyc > parts ? m->cyc - parts : 0u));
}
#endif

/* Prints the [prof] cycle profile (the measure build; a one-line note otherwise). */
static void print_profile(void)
{
#if !USB_PROFILE
    tap_printf("[prof]  compiled out (USB_PROFILE=0): no cycle profile in this build\n");
    return;
#endif
    if (!g_prof_ok) {
        tap_printf("[prof]  cycle counter unavailable -- profile figures invalid\n");
        return;
    }

    uint64_t iters = g_prof_iters ? g_prof_iters : 1u;
    uint64_t pkt   = g_decoder.prof_pkt_cyc;
    uint64_t run   = g_prof_run_cyc;
    /* usb_decode_run minus the packet decoding inside it = the scan loop. */
    uint64_t scan  = (run > pkt) ? (run - pkt) : 0u;
    uint64_t acct  = g_prof_poll_cyc + run + g_prof_flush_cyc;

    /* Wall cycles over the session, from the capture clock: words x 16 sample clocks x cycles per
     * sample clock. */
    uint64_t wall = (uint64_t)((double)g_capture.total_written *
                               (double)clock_get_hz(clk_sys) /
                               ((double)g_capture.sample_hz /
                                (double)USB_CAPTURE_SAMPLES_PER_WORD));

    uint64_t exam = g_decoder.idle_words_skipped + g_decoder.se0_words +
                    g_decoder.nonidle_words + g_decoder.packet_words;

    /* The budget follows the clock: cycles per sample word is clk_sys over the word rate. */
    double budget_word = (double)clock_get_hz(clk_sys) /
                         ((double)g_capture.sample_hz /
                          (double)USB_CAPTURE_SAMPLES_PER_WORD);
    double budget_bit  = budget_word / (double)g_capture.oversample;

    /* Words per pass first: far less than a packet (~135 words) and the decoder cannot finish
     * packets. */
    tap_printf("[prof]  core1 iters=%llu  passes=%llu (%.0f words/pass)"
           "  loop=%llu  wall=%llu  busy=%.1f%%\n",
           (unsigned long long)iters, (unsigned long long)g_prof_passes,
           g_prof_passes ? (double)exam / (double)g_prof_passes : 0.0,
           (unsigned long long)g_prof_loop_cyc, (unsigned long long)wall,
           wall ? 100.0 * (double)g_prof_loop_cyc / (double)wall : 0.0);
#if !USB_PROFILE_DETAIL
    /* Without the decoder's breakdown, run is scan and packet decoding together. */
    (void)pkt; (void)scan; (void)budget_word; (void)budget_bit;
    tap_printf("        spin=%llu (%.0f cyc/iter)  poll=%llu (%.0f cyc/pass)"
           "  run=%llu  flush=%llu\n",
           (unsigned long long)g_prof_spin_cyc,
           (double)g_prof_spin_cyc / (double)iters,
           (unsigned long long)g_prof_poll_cyc,
           g_prof_passes ? (double)g_prof_poll_cyc / (double)g_prof_passes : 0.0,
           (unsigned long long)run, (unsigned long long)g_prof_flush_cyc);
    tap_printf("        run:    %.2f cyc/word over %llu words read; decoder breakdown"
           " compiled out (USB_PROFILE_DETAIL=0)\n",
           g_capture.total_read ? (double)run / (double)g_capture.total_read : 0.0,
           (unsigned long long)g_capture.total_read);
#else
    tap_printf("        spin=%llu (%.0f cyc/iter)  poll=%llu (%.0f cyc/pass)"
           "  run=%llu  scan=%llu  packet=%llu  flush=%llu\n",
           (unsigned long long)g_prof_spin_cyc,
           (double)g_prof_spin_cyc / (double)iters,
           (unsigned long long)g_prof_poll_cyc,
           g_prof_passes ? (double)g_prof_poll_cyc / (double)g_prof_passes : 0.0,
           (unsigned long long)run,
           (unsigned long long)scan, (unsigned long long)pkt,
           (unsigned long long)g_prof_flush_cyc);

    uint64_t scan_words = g_decoder.idle_words_skipped + g_decoder.se0_words +
                          g_decoder.nonidle_words;
    if (scan_words) {
        tap_printf("        scan:   %.2f cyc/word over %llu words\n",
               (double)scan / (double)scan_words,
               (unsigned long long)scan_words);
    }
    if (g_decoder.packet_words) {
        tap_printf("        packet: %.1f cyc/word over %llu words"
               "  = %.1f cyc/bus-bit (budget %.0f/word, %.0f/bit)\n",
               (double)pkt / (double)g_decoder.packet_words,
               (unsigned long long)g_decoder.packet_words,
               (double)pkt / (double)g_decoder.packet_words /
                   (double)g_capture.oversample,
               budget_word, budget_bit);
    }
    if (g_decoder.prof_pkt_calls) {
        /* The per-call work (CRC, PID checks, MSC parse, callbacks) apart from the per-word sample
         * loop. */
        uint64_t fin   = g_decoder.prof_finish_cyc;
        uint64_t wloop = (pkt > fin) ? (pkt - fin) : 0u;
        tap_printf("        packet: %.0f cyc per decode_packet() call over %llu"
               " calls  (finish %.0f + sample loop %.0f)\n",
               (double)pkt / (double)g_decoder.prof_pkt_calls,
               (unsigned long long)g_decoder.prof_pkt_calls,
               (double)fin / (double)g_decoder.prof_pkt_calls,
               (double)wloop / (double)g_decoder.prof_pkt_calls);
        if (g_decoder.packet_words) {
            tap_printf("        packet: sample loop %.1f cyc/word = %.1f"
                   " cyc/bus-bit (budget %.0f/bit)  se0_cand=%.2f/word\n",
                   (double)wloop / (double)g_decoder.packet_words,
                   (double)wloop / (double)g_decoder.packet_words /
                       (double)g_capture.oversample,
                   budget_bit,
                   (double)g_decoder.prof_se0_bits /
                       (double)g_decoder.packet_words);
        }

        /* Option A's split: passing over file data, against decoding everything else. */
        uint64_t skip_cyc  = g_decoder.prof_skip_cyc;
        uint64_t dec_cyc   = (wloop > skip_cyc) ? (wloop - skip_cyc) : 0u;
        uint64_t dec_words = g_decoder.packet_words - g_decoder.skip_words;
        uint64_t dec_calls = g_decoder.prof_pkt_calls - g_decoder.packets_skipped;
        if (g_decoder.skip_words) {
            tap_printf("        skip:   %.1f cyc/word over %llu words (%llu packets)\n",
                   (double)skip_cyc / (double)g_decoder.skip_words,
                   (unsigned long long)g_decoder.skip_words,
                   (unsigned long long)g_decoder.packets_skipped);
        }
        if (dec_words && dec_calls) {
            tap_printf("        decode: %.1f cyc/word over %llu words, %.0f cyc per"
                   " non-skipped call\n",
                   (double)dec_cyc / (double)dec_words,
                   (unsigned long long)dec_words,
                   (double)dec_cyc / (double)dec_calls);
        }

        /* Inside each half: the plain-word loop against everything else. */
        uint64_t sp_cyc   = g_decoder.prof_skip_plain_cyc;
        uint64_t sp_words = g_decoder.prof_skip_plain_words;
        if (g_decoder.skip_words) {
            uint64_t sg_words = g_decoder.skip_words - sp_words;
            uint64_t sg_cyc   = (skip_cyc > sp_cyc) ? (skip_cyc - sp_cyc) : 0u;
            tap_printf("        skip:   plain run %.1f cyc/word over %llu words (%.1f%%);"
                   " general %llu words, %.0f cyc per word or %.0f per packet\n",
                   sp_words ? (double)sp_cyc / (double)sp_words : 0.0,
                   (unsigned long long)sp_words,
                   100.0 * (double)sp_words / (double)g_decoder.skip_words,
                   (unsigned long long)sg_words,
                   sg_words ? (double)sg_cyc / (double)sg_words : 0.0,
                   g_decoder.packets_skipped ?
                       (double)sg_cyc / (double)g_decoder.packets_skipped : 0.0);
            uint64_t s_se0 = g_decoder.skip_fallback_se0;
            tap_printf("        skip:   general words: %llu hold SE0 (%.2f per packet; 1 is the EOP),"
                   " %llu rule stops\n",
                   (unsigned long long)s_se0,
                   g_decoder.packets_skipped ?
                       (double)s_se0 / (double)g_decoder.packets_skipped : 0.0,
                   (unsigned long long)(sg_words > s_se0 ? sg_words - s_se0 : 0u));
        }
        uint64_t dp_cyc   = g_decoder.prof_plain_cyc;
        uint64_t dp_words = g_decoder.prof_plain_words;
        uint64_t tail     = g_decoder.prof_tail_cyc;
        if (dec_words && dec_calls) {
            uint64_t dg_words = (dec_words > dp_words) ? (dec_words - dp_words) : 0u;
            uint64_t dg_cyc   = (dec_cyc > dp_cyc + tail) ? (dec_cyc - dp_cyc - tail) : 0u;
            tap_printf("        decode: plain run %.1f cyc/word over %llu words (%.1f%%);"
                   " general %llu words + setup %.0f cyc per call; tail %.0f per call\n",
                   dp_words ? (double)dp_cyc / (double)dp_words : 0.0,
                   (unsigned long long)dp_words,
                   100.0 * (double)dp_words / (double)dec_words,
                   (unsigned long long)dg_words,
                   (double)dg_cyc / (double)dec_calls,
                   (double)tail / (double)dec_calls);
            tap_printf("        decode: plain run calls %llu (%.2f per decoded packet)\n",
                   (unsigned long long)g_decoder.prof_plain_calls,
                   (double)g_decoder.prof_plain_calls / (double)dec_calls);
            uint64_t d_first = g_decoder.dec_fallback_first;
            uint64_t d_se0   = g_decoder.dec_fallback_se0;
            tap_printf("        decode: general words: %llu first words, %llu hold SE0,"
                   " %llu rule stops\n",
                   (unsigned long long)d_first, (unsigned long long)d_se0,
                   (unsigned long long)(dg_words > d_first + d_se0 ?
                                        dg_words - d_first - d_se0 : 0u));
        }
    }
#endif /* USB_PROFILE_DETAIL */
    tap_printf("        unaccounted (stall/other) = %lld cyc (%.1f%% of wall)\n",
           (long long)((int64_t)g_prof_loop_cyc - (int64_t)acct),
           wall ? 100.0 * (double)((int64_t)g_prof_loop_cyc - (int64_t)acct) /
                  (double)wall : 0.0);
}


/* When the current stats part began: the printing time is charged to it as it goes. */
static uint64_t g_stats_part_t0;

/* Between two stats lines: charges the printing time to the stats part and services the link. */
static void stats_pump(void)
{
    g_stats_part_t0 = gap_mark(GAP_STATS, g_stats_part_t0);
    meta_service();
    g_stats_part_t0 = time_us_64();
}


/* Stack use, measured: core0's 4 KB above core1's stack; both are painted at boot and the deepest
 * use is reported. */
#define STACK_PAINT 0x5AC4D00Du
extern uint32_t __StackOneBottom, __StackOneTop, __StackTop;

/* Fills a stack region with the pattern, so its deepest use can be found later. */
static void stack_paint(uint32_t *from, uint32_t *to)
{
    while (from < to) {
        *from++ = STACK_PAINT;
    }
}

/* Bytes used: the region from `from` up to `to`, less the untouched pattern at its low end. */
static uint32_t stack_used(const uint32_t *from, const uint32_t *to)
{
    const uint32_t *p = from;
    while (p < to && *p == STACK_PAINT) {
        p++;
    }
    return (uint32_t)((to - p) * sizeof(uint32_t));
}


/* Prints the whole stats block (key s, and every 10 s), servicing the link between lines. */
static void print_stats(void)
{
    g_stats_part_t0 = time_us_64();
    usb_decoder_print_stats(&g_decoder, &g_capture);
    stats_pump();
    print_profile();
    stats_pump();
    msc_parser_print_stats(&g_parser);
    stats_pump();
    tap_printf("[log]   records=%llu  queue_drops: cmd=%llu evt=%llu\n",
           (unsigned long long)g_log.records,
           (unsigned long long)g_dropped_cmds,
           (unsigned long long)g_dropped_evts);
    for (uint32_t i = 0; i < g_store.count; i++) {
        const store_backend_t *const b = g_store.backend[i];
        stats_pump();
        tap_printf("[store] %s: items=%llu bytes=%llu failures=%llu (failures must be 0)\n",
               b->name, (unsigned long long)b->items, (unsigned long long)b->bytes,
               (unsigned long long)b->failures);
    }
    tap_printf("[store] %s (behind %s): items=%llu bytes=%llu failures=%llu (failures must be 0)\n",
           g_console_any.name, g_console_fifo_b.name, (unsigned long long)g_console_any.items,
           (unsigned long long)g_console_any.bytes, (unsigned long long)g_console_any.failures);
    tap_printf("[store] %s holds %lu bytes now, high-water %lu of %u\n",
           g_console_fifo_b.name, (unsigned long)store_fifo_held(&g_console_fifo),
           (unsigned long)g_console_fifo.high_water, (unsigned)CONSOLE_FIFO_BYTES);
    stats_pump();
    print_sd_stats();
    stats_pump();
    print_vbus_stats();
    stats_pump();
    print_bus_notes();
    stats_pump();
    print_model_stats();
    stats_pump();
    tap_printf("[meta]  core1 copy: chunks=%llu words=%llu dropped=%llu (link full), skipped=%llu (core1 behind),"
           " high-water %lu of %u words\n",
           (unsigned long long)g_meta_link.chunks, (unsigned long long)g_meta_link.words,
           (unsigned long long)g_meta_link.drops, (unsigned long long)g_meta_link.behind_skips,
           (unsigned long)g_meta_link.high_water, (unsigned)META_LINK_WORDS);
    tap_printf("[meta]  core0 decode: chunks=%llu spans=%llu holes=%llu complete=%llu incomplete=%llu"
           " re-sent CBWs=%llu bad chunks=%llu; sectors new=%llu repeated=%llu; longest time the link"
           " was left unattended %.1f ms\n",
           (unsigned long long)g_meta_rx.chunks, (unsigned long long)g_meta_rx.spans,
           (unsigned long long)g_meta_rx.holes, (unsigned long long)g_meta_rx.complete,
           (unsigned long long)g_meta_rx.incomplete, (unsigned long long)g_meta_rx.dup_cbws,
           (unsigned long long)g_meta_rx.bad_chunks, (unsigned long long)g_sectors_new,
           (unsigned long long)g_sectors_repeated, (double)g_meta_pump_gap_max_us / 1000.0);
#if TAP_MEASURE
    {
        /* core0's decode work in its own cycles (DWT), not in time inside meta_rx_pump (mostly
         * empty calls). */
        const uint64_t work_cyc = g_meta_rx.decode_cyc + g_meta_rx.feed_cyc + g_meta_rx.restart_cyc;
        const double words = g_meta_rx.words ? (double)g_meta_rx.words : 1.0;
        stats_pump();
        tap_printf("[meta]  core0 decode: %llu words in %llu cycles = %.0f per word (decoder %.0f with results,"
               " chunk copy %.1f): capacity %.0f words/s, core1 copies up to 3,000,000/s; time in calls that"
               " decoded %.2f s%s\n",
               (unsigned long long)g_meta_rx.words, (unsigned long long)work_cyc, (double)work_cyc / words,
               (double)g_meta_rx.decode_cyc / words, (double)g_meta_rx.feed_cyc / words,
               work_cyc ? words * (double)clock_get_hz(clk_sys) / (double)work_cyc : 0.0,
               (double)g_meta_busy_us / 1e6, g_core0_cyc_ok ? "" : " (DWT NOT RUNNING: cycle figures are 0)");
    tap_printf("[meta]  busiest %.1f ms of bus: core1 needed to copy %lu words = %.2f M words/s, %.0f%% of the bus; core0 decodes %.2f M/s; windows over three quarters: %lu, longest run %lu (%.0f ms)\n",
           (double)(1u << META_WIN_SHIFT) / 3000.0,
           (unsigned long)g_meta_link.win_peak,
           (double)g_meta_link.win_peak * 3.0 / (double)(1u << META_WIN_SHIFT),
           100.0 * (double)g_meta_link.win_peak / (double)(1u << META_WIN_SHIFT),
           work_cyc ? (double)clock_get_hz(clk_sys) * words / (double)work_cyc / 1e6 : 0.0,
           (unsigned long)g_meta_link.win_loaded,
           (unsigned long)g_meta_link.win_run_max,
           (double)g_meta_link.win_run_max * (double)(1u << META_WIN_SHIFT) / 3000.0);
        {
            /* Where core0's decode cycles go, per copied word: bit decoding, CRC16, the packet and
             * result callbacks. */
            const uint64_t pk  = g_meta_rx.packet_cyc;
            const uint64_t res = g_meta_rx.result_cyc < pk ? g_meta_rx.result_cyc : pk;
            const uint64_t crc = meta_crc16_cyc;
            const uint64_t dec = g_meta_rx.decode_cyc;
            const uint64_t bits = dec > pk + crc ? dec - pk - crc : 0u;
            tap_printf("[meta]  core0 decode split, cycles per copied word: bit decoding %.0f, CRC16 %.0f"
                   " (%.1f per byte over %llu bytes), packet callback %.0f, results %.0f (exFAT model %.1f, of"
                   " which [names] events %.1f; sector hashing and SEC items %.1f; directory check %.1f),"
                   " chunk copy %.1f\n",
                   (double)bits / words, (double)crc / words,
                   meta_crc16_bytes ? (double)crc / (double)meta_crc16_bytes : 0.0,
                   (unsigned long long)meta_crc16_bytes, (double)(pk - res) / words, (double)res / words,
                   (double)g_model_cyc / words, (double)g_names_cyc / words, (double)g_sector_cyc / words,
                   (double)g_expect_cyc / words, (double)g_meta_rx.feed_cyc / words);
        }
        {
            /* Per packet kind, its share of core0's decode cycles and of the copied words. */
            static const char *const kind_name[6] = { "transfer DATA", "CBW/CSW/other DATA", "IN/OUT/SETUP",
                                                      "SOF", "handshakes", "other" };
            const double ns_per_word = (double)g_capture.ns_per_sample_q16 * 16.0 / 65536.0;
            const double dec = g_meta_rx.decode_cyc ? (double)g_meta_rx.decode_cyc : 1.0;
            char line[480];
            int o = snprintf(line, sizeof line, "[meta]  core0 decode by packet kind (n, %% of decode cycles,"
                             " %% of copied words):");
            uint64_t charged = 0;
            for (unsigned k = 0; k < 6u && o > 0 && o < (int)sizeof line; k++) {
                charged += g_meta_rx.kind_cyc[k];
                const double w = (double)g_meta_rx.kind_pkt_words[k] + (double)g_meta_rx.kind_gap_ns[k] / ns_per_word;
                o += snprintf(line + o, sizeof line - (size_t)o, " %s %llu %.1f%% %.1f%%;", kind_name[k],
                              (unsigned long long)g_meta_rx.kind_n[k], 100.0 * (double)g_meta_rx.kind_cyc[k] / dec,
                              100.0 * w / words);
            }
            tap_printf("%s after each call's last packet %.1f%% of cycles\n", line,
                   g_meta_rx.decode_cyc > charged ? 100.0 * (double)(g_meta_rx.decode_cyc - charged) / dec : 0.0);
            /* Re-walks of packets left incomplete at a decode call's end. */
            tap_printf("[meta]  core0 decoder: incomplete attempts %llu, words walked again %llu (%.1f%% of copied words)\n",
                   (unsigned long long)g_meta_rx.dec.incomplete_calls, (unsigned long long)g_meta_rx.dec.rewalk_words,
                   100.0 * (double)g_meta_rx.dec.rewalk_words / words);
        }
        stats_pump();
        tap_printf("[meta]  core0 bursts (link over half full: decoding up to %u ms before other work): %llu,"
               " longest call %.1f ms; results handled in %.2f s\n",
               (unsigned)(META_BURST_US / 1000u), (unsigned long long)g_meta_bursts,
               (double)g_meta_burst_max_us / 1000.0, (double)g_meta_result_us / 1e6);
        /* Bus time inside complete transfers, as words (3,000 per ms), against core1's copied
         * words. */
        for (unsigned w = 0; w < 2u; w++) {
            const uint64_t n = g_meta_rx.phase_cmds[w];
            tap_printf("[meta]  complete %s bus time: %llu commands, CBW to first data %.1f ms, data %.1f ms,"
                   " last data to CSW %.1f ms; total %.0f k words (%.1f k per command)\n",
                   w ? "WRITEs'" : "READs'", (unsigned long long)n,
                   (double)g_meta_rx.phase_to_data_ns[w] / 1e6, (double)g_meta_rx.phase_data_ns[w] / 1e6,
                   (double)g_meta_rx.phase_to_csw_ns[w] / 1e6,
                   (double)(g_meta_rx.phase_to_data_ns[w] + g_meta_rx.phase_data_ns[w] +
                            g_meta_rx.phase_to_csw_ns[w]) * 3e-6,
                   n ? (double)(g_meta_rx.phase_to_data_ns[w] + g_meta_rx.phase_data_ns[w] +
                                g_meta_rx.phase_to_csw_ns[w]) * 3e-6 / (double)n : 0.0);
        }
    }
#endif
    stats_pump();
    tap_printf("[store] sectors: to the card %llu (refused %llu), to the console %llu (refused %llu; only"
           " when there is no card) -- refusals must be 0\n",
           (unsigned long long)g_sd_sectors_given, (unsigned long long)g_sd_sectors_refused,
           (unsigned long long)g_sectors_to_console, (unsigned long long)g_sectors_console_refused);
    stats_pump();
    uint32_t empty_known = 0;   /* directory sectors known empty without being cached */
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
        empty_known += g_exfat.empty[i] != EXFAT_EMPTY_NONE ? 1u : 0u;
    }
    tap_printf("[names] volume %s: sectors fed=%llu directory sectors=%llu events=%llu"
           " sets not matching checksum=%llu directories=%lu (not tracked %llu, forgotten when deleted %llu, of them inside a deleted"
           " directory %llu)"
           " cache evictions=%llu, empty sectors known by LBA=%lu of %u (forgotten, list full: %llu),"
           " of the directory sectors %llu were already cached and not parsed again;"
           " changes not reported (over %u in one transfer, each warned)=%llu;"
           " core1 filter %s (%lu extents)\n",
           !g_exfat.have_volume ? "unknown" : g_exfat.volume_confirmed ? "known" : "remembered (awaiting its boot sector)",
           (unsigned long long)g_exfat.sectors,
           (unsigned long long)g_exfat.dir_sectors, (unsigned long long)g_exfat.events,
           (unsigned long long)g_exfat.bad_sets, (unsigned long)g_exfat.ndirs,
           (unsigned long long)g_exfat.dirs_full, (unsigned long long)g_exfat.dirs_forgotten,
           (unsigned long long)g_exfat.dirs_forgotten_inside,
           (unsigned long long)g_exfat.evictions, (unsigned long)empty_known, (unsigned)EXFAT_EMPTY_SECTORS,
           (unsigned long long)g_exfat.empty_full, (unsigned long long)g_exfat.dir_sectors_same,
           (unsigned)EXFAT_MAX_CHANGES, (unsigned long long)g_names_changes_lost,
           g_meta_link.interest_active ? "on: directory extents"
               : (g_meta_link.single_block_until_known ? "single-sector transfers until the volume is known"
                                                       : "off"),
           (unsigned long)g_meta_link.interest_count);
    stats_pump();
    tap_printf("[names] directory commands checked=%llu complete=%llu; WRITEs not decoded whole=%llu (must be 0:"
           " each printed a WARNING and sealed a FILE UNRELIABLE record); READs missed or partial=%llu;"
           " of the missing, reported because the check's table was full=%llu\n",
           (unsigned long long)g_expect.expected, (unsigned long long)g_expect.complete,
           (unsigned long long)g_dir_writes_unreliable, (unsigned long long)g_dir_reads_missed,
           (unsigned long long)g_expect.evicted);
    stats_pump();
    /* The iteration that prints this is not yet counted in it. */
    stats_pump();
    tap_printf("[core0] queue high-water: cmd %lu of %u, evt %lu of %u\n",
           (unsigned long)g_cmd_high, (unsigned)CMD_QUEUE_DEPTH,
           (unsigned long)g_evt_high, (unsigned)EVT_QUEUE_DEPTH);
#if TAP_MEASURE
    tap_printf("[core0] longest main-loop iteration %.1f ms (longest queue drain %.1f ms)\n",
           (double)g_core0_iter_max_us / 1000.0, (double)g_core0_drain_max_us / 1000.0);
    /* The parts of the longest absence from the link (the main loop minus meta_service): they add
     * up to the gap. */
    tap_printf("[core0] longest time the link was left unattended during the session %.1f ms, spent in:",
           (double)g_meta_pump_gap_max_us / 1000.0);
    for (unsigned i = 0; i < GAP_PARTS; i++) {
        tap_printf(" %s %.1f ms%s", g_gap_name[i], (double)g_gap_max_us[i] / 1000.0,
               i + 1u == GAP_PARTS ? "\n" : ",");
    }
#endif
    {
        const uint32_t used0 = stack_used(&__StackOneTop, &__StackTop);
        const uint32_t used1 = stack_used(&__StackOneBottom, &__StackOneTop);
        const uint32_t room0 = (uint32_t)((&__StackTop - &__StackOneTop) * sizeof(uint32_t));
        const uint32_t room1 = (uint32_t)((&__StackOneTop - &__StackOneBottom) * sizeof(uint32_t));
        stats_pump();
        tap_printf("[core0] stacks, deepest use since boot: core0 %lu of %lu bytes before core1's stack,"
               " core1 %lu of %lu%s\n",
               (unsigned long)used0, (unsigned long)room0, (unsigned long)used1, (unsigned long)room1,
               used0 > room0 - room0 / 4u ? " -- WARNING: core0 within a quarter of core1's stack" : "");
    }
#if TAP_MEASURE
    stats_pump();
    tap_printf("[core0] while the link was over a quarter full: %.2f s of main loop, decoding %.2f s, queue drain"
           " and record printing %.2f s, other %.2f s; pumps held back: console %llu, sector %llu\n",
           (double)g_busy_us / 1e6, (double)g_busy_meta_us / 1e6, (double)g_busy_drain_us / 1e6,
           g_busy_us > g_busy_meta_us + g_busy_drain_us
               ? (double)(g_busy_us - g_busy_meta_us - g_busy_drain_us) / 1e6 : 0.0,
           (unsigned long long)g_console_held_back, (unsigned long long)g_sector_held_back);
#endif
    stats_pump();
    tap_printf("[cap]   overwrite-suspect passes=%llu (must be 0: else a decode pass may"
           " have read ring words the DMA had already overwritten)\n",
           (unsigned long long)g_overwrite_suspect);
    stats_pump();
    tap_printf("[load]  250 ms windows: busiest had %lu file-data packets (%.0f/s) and lost"
           " %lu words; %llu windows with file data, %llu lossy (avg %.0f file-data"
           " packets/s)\n",
           (unsigned long)g_win_peak_pkts, 4.0 * (double)g_win_peak_pkts,
           (unsigned long)g_win_peak_lost,
           (unsigned long long)g_win_active, (unsigned long long)g_win_lossy,
           g_win_lossy ? 4.0 * (double)g_win_lossy_pkts / (double)g_win_lossy : 0.0);
#if USB_PROFILE
    /* Spare time: spin cycles over loop cycles. 0% = core1 never waited. */
    stats_pump();
    tap_printf("[load]  core1 spare (spin share of loop cycles): busiest window %.1f%%;"
           " least spare window with file data %.1f%% (%lu file-data packets, %.0f/s)\n",
           g_win_peak_loop ? 100.0 * (double)g_win_peak_spin / (double)g_win_peak_loop : 0.0,
           g_win_min_loop ? 100.0 * (double)g_win_min_spin / (double)g_win_min_loop : 0.0,
           (unsigned long)g_win_min_pkts, 4.0 * (double)g_win_min_pkts);
    /* The same by direction: busy cycles per file-data packet against the cycles the window held,
     * so "under" is the margin. */
    {
        static const char *const name[2] = { "WRITE", "READ" };
        const double hz = (double)clock_get_hz(clk_sys);
        /* Built whole, then printed with one printf (see the [bus] line). */
        char line[400];
        size_t pos = 0;
        int n = snprintf(line, sizeof(line), "[load]  least spare by direction:");
        pos = n > 0 ? (size_t)n : 0u;
        for (int k = 1; k >= 0 && pos < sizeof(line); k--) {
            const win_rec_t *const m = &g_win_min_dir[k];
            const char *const end = k ? ";" : "";
            if (m->pkts == 0u || m->dur_us == 0u) {
                n = snprintf(line + pos, sizeof(line) - pos, " %s windows %llu%s", name[k],
                             (unsigned long long)g_win_dir_count[k], end);
            } else {
                const double busy   = (double)(m->loop - m->spin) / (double)m->pkts;
                const double budget = hz * ((double)m->dur_us / 1e6) / (double)m->pkts;
                n = snprintf(line + pos, sizeof(line) - pos,
                             " %s windows %llu, least spare %.1f%% at %.0f file-data packets/s"
                             " (busy %.0f of %.0f cycles per packet, %.1f%% under)%s",
                             name[k], (unsigned long long)g_win_dir_count[k],
                             100.0 * (double)m->spin / (double)m->loop,
                             (double)m->pkts * 1e6 / (double)m->dur_us,
                             busy, budget, 100.0 * (1.0 - busy / budget), end);
            }
            pos += n > 0 ? (size_t)n : 0u;
        }
        tap_printf("%s\n", line);
    }
    print_iter("[stall] longest core1 iteration of the session", &g_iter_max);
#endif
    /* The rest of this function is timed here: the loop restarts its clock after print_stats
     * returns. */
    (void)gap_mark(GAP_STATS, g_stats_part_t0);
}

/* Prints raw sample words, to show the PIO sees line activity before trusting any decode. */
static void print_raw(void)
{
    tap_printf("[raw]   words: total=%llu idle=%llu non-idle=%llu se0=%llu\n",
           (unsigned long long)g_capture.total_written,
           (unsigned long long)g_decoder.idle_words_skipped,
           (unsigned long long)g_decoder.nonidle_words,
           (unsigned long long)g_decoder.se0_words);
    tap_printf("        last non-idle samples:");
    uint32_t n = g_decoder.raw_count;
    if (n == 0) {
        tap_printf(" (none -- bus idle, or the tap is not connected)");
    }
    for (uint32_t i = 0; i < n && i < USB_DECODE_RAW_SLOTS; i++) {
        tap_printf(" %08lx", (unsigned long)g_decoder.raw_words[i]);
    }
    tap_printf("\n");
    g_decoder.raw_count = 0;
}
