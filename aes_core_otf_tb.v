// ============================================================
// aes_core_otf_tb.v -- Testbench for aes_core_otf, parameterized
// over KEY_BITS (128/192/256). Uses the official FIPS-197
// Appendix C known-answer test vectors. Same structure as
// aes_core_tb.v (including the out_ready stall check) so the two
// cores' behavior can be compared directly.
//
//   iverilog -o sim sbox.v sub_bytes.v shift_rows.v mix_columns.v \
//     add_round_key.v key_expansion_otf.v aes_core_otf.v aes_core_otf_tb.v
//
// No compiler flags needed -- edit KEY_BITS below directly and
// recompile. (A `define-based override used to live here; it was
// removed because the compile-time-macro syntax for setting it
// differs across tools -- e.g. `-DTB_KEY_BITS=128` for Icarus vs.
// `+define+TB_KEY_BITS=128` for ModelSim/Questa's vlog -- and an
// unset/mis-set macro silently falls back to its default with no
// warning, which is easy to miss. A plain localparam you edit by
// hand avoids that failure mode entirely.)
// ============================================================
`timescale 1ns/1ps

module aes_core_otf_tb;

    localparam integer KEY_BITS = 256;   // <<< EDIT THIS: 128, 192, or 256

    reg                  clk;
    reg                  rst_n;

    reg                  in_valid;
    wire                 in_ready;
    reg  [KEY_BITS-1:0]  key;
    reg  [127:0]         plaintext;

    wire                 out_valid;
    reg                  out_ready;
    wire [127:0]         ciphertext;

    localparam [127:0] PLAINTEXT_VEC = 128'h00000000000000000000000000000000;

    localparam [255:0] KEY_128_FULL = 256'hfffffffffffffffffffffffff8000000;
    localparam [255:0] KEY_192_FULL = 256'hfffffffffffffffffffffffff80000000000000000000000;
    localparam [255:0] KEY_256_FULL = 256'hfffffffffffffffffffffffff800000000000000000000000000000000000000;

    localparam [255:0] KEY_SEL = (KEY_BITS == 128) ? KEY_128_FULL :
                                  (KEY_BITS == 192) ? KEY_192_FULL :
                                                       KEY_256_FULL;

    localparam [127:0] EXPECTED_CIPHERTEXT =
        (KEY_BITS == 128) ? 128'h829c04ff4c07513c0b3ef05c03e337b5 :
        (KEY_BITS == 192) ? 128'h03194b8e5dda5530d0c678c0b48f5d92 :
                             128'h40b264e921e9e4a82694589ef3798262;

    aes_core_otf #(
        .KEY_BITS (KEY_BITS)
    ) dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .in_valid   (in_valid),
        .in_ready   (in_ready),
        .key        (key),
        .plaintext  (plaintext),
        .out_valid  (out_valid),
        .out_ready  (out_ready),
        .ciphertext (ciphertext)
    );

    function [63:0] state_name;
        input [2:0] s;
        begin
            case (s)
                3'd0: state_name = "IDLE";
                3'd1: state_name = "LOAD";
                3'd2: state_name = "ROUND";
                3'd3: state_name = "FINAL";
                3'd4: state_name = "OUT";
                default: state_name = "??";
            endcase
        end
    endfunction

    always @(posedge clk) begin
        if (rst_n) begin
            $display("t=%0t | state=%-5s | round=%0d | data_reg=%h | rk_idx=%0d round_key=%h | ld=%b nx=%b",
                      $time, state_name(dut.state), dut.round_cnt, dut.data_reg,
                      dut.round_key_rk_idx, dut.round_key, dut.key_exp_load, dut.key_exp_next);
        end
    end

    initial clk = 1'b0;
    always #5 clk = ~clk;

    integer cycle_count;

    // All stimulus changes happen #1 after the clock edge, strictly after
    // the DUT's own synchronous updates for that edge have resolved -- 
    // avoids any same-timestep race between this process and the DUT's
    // (or key_expansion_otf's) always @(posedge clk) blocks.
    task run_one_block;
        input [127:0] pt;
        begin
            @(posedge clk); #1;
            in_valid  = 1'b1;
            key       = KEY_SEL[KEY_BITS-1:0];
            plaintext = pt;

            wait (in_valid && in_ready);
            cycle_count = 0;
            @(posedge clk); #1;
            in_valid = 1'b0;

            out_ready = 1'b0;
            while (!out_valid) begin
                @(posedge clk);
                cycle_count = cycle_count + 1;
            end
            repeat (3) @(posedge clk); #1;
            out_ready = 1'b1;

            wait (out_valid && out_ready);
            @(posedge clk); #1;
            out_ready = 1'b0;
        end
    endtask

    initial begin
        rst_n     = 1'b0;
        in_valid  = 1'b0;
        out_ready = 1'b0;
        key       = {KEY_BITS{1'b0}};
        plaintext = 128'h0;

        repeat (3) @(posedge clk); #1;
        rst_n = 1'b1;
        @(posedge clk); #1;

        $display("---------------------------------------------------------------");
        $display("KEY_BITS  = %0d", KEY_BITS);
        $display("plaintext = %h", PLAINTEXT_VEC);
        $display("---------------------------------------------------------------");

        run_one_block(PLAINTEXT_VEC);

        $display("---------------------------------------------------------------");
        $display("cycles from handshake to out_valid: %0d", cycle_count);
        if (ciphertext === EXPECTED_CIPHERTEXT) begin
            $display("PASS: ciphertext = %h", ciphertext);
        end else begin
            $display("FAIL: got %h, expected %h", ciphertext, EXPECTED_CIPHERTEXT);
        end

        #20 $finish;
    end

endmodule