
// KEY_BITS (128/192/256). Uses the official FIPS-197 Appendix C

`timescale 1ns/1ps

`ifndef TB_KEY_BITS
`define TB_KEY_BITS 128
`endif

module aes_core_tb;

    localparam integer KEY_BITS = `TB_KEY_BITS;

    reg                  clk;
    reg                  rst_n;

    reg                  in_valid;
    wire                 in_ready;
    reg  [KEY_BITS-1:0]  key;
    reg  [127:0]         plaintext;
    reg                  in_last;

    wire                 out_valid;
    reg                  out_ready;
    wire [127:0]         ciphertext;
    wire                 out_last;

    // Use values from test vector files. Found in 'aes test vec' folder, or in nist website.
    localparam [127:0] PLAINTEXT_VEC = 128'h58c8e00b2631686d54eab84b91f0aca1;

    localparam [255:0] KEY_128_FULL = 256'h00000000000000000000000000000000;
    localparam [255:0] KEY_192_FULL = 256'h000102030405060708090a0b0c0d0e0f1011121314151617;
    localparam [255:0] KEY_256_FULL = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;

    localparam [255:0] KEY_SEL = (KEY_BITS == 128) ? KEY_128_FULL :
                                  (KEY_BITS == 192) ? KEY_192_FULL :
                                                       KEY_256_FULL;

    localparam [127:0] EXPECTED_CIPHERTEXT =
        (KEY_BITS == 128) ? 128'h08a4e2efec8a8e3312ca7460b9040bbf :
        (KEY_BITS == 192) ? 128'hdda97ca4864cdfe06eaf70a0ec0d7191 :
                             128'h8ea2b7ca516745bfeafc49904b496089;

    aes_core #(
        .KEY_BITS (KEY_BITS)
    ) dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .in_valid   (in_valid),
        .in_ready   (in_ready),
        .key        (key),
        .plaintext  (plaintext),
        .in_last    (in_last),
        .out_valid  (out_valid),
        .out_ready  (out_ready),
        .ciphertext (ciphertext),
        .out_last   (out_last)
    );

    // ---- State-name decode for display (mirrors dut's localparams) ----
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
            $display("t=%0t | state=%-5s | round=%0d | data_reg=%h | in_v=%b in_r=%b in_last=%b | out_v=%b out_r=%b out_last=%b",
                      $time, state_name(dut.state), dut.round_cnt, dut.data_reg,
                      in_valid, in_ready, in_last, out_valid, out_ready, out_last);
        end
    end

    // 100 MHz clock
    initial clk = 1'b0;
    always #5 clk = ~clk;

    reg last_check_ok;

    // Drives one in_valid/in_ready handshake (with a given in_last), then
    // holds out_ready low for a few cycles before accepting the result, to
    // exercise the stall path. Checks that out_last matches what went in.
    task run_one_block;
        input        last_in;
        input [127:0] pt;
        begin
            @(posedge clk);
            in_valid  = 1'b1;
            key       = KEY_SEL[KEY_BITS-1:0];
            plaintext = pt;
            in_last   = last_in;

            // wait for the handshake to actually complete
            wait (in_valid && in_ready);
            @(posedge clk);
            in_valid = 1'b0;

            // deliberately stall the output side for a bit
            out_ready = 1'b0;
            wait (out_valid == 1'b1);
            repeat (3) @(posedge clk);   // out_valid/ciphertext/out_last must stay stable
            if (out_last !== last_in) begin
                $display("FAIL: out_last=%b did not match in_last=%b for this block", out_last, last_in);
                last_check_ok = 1'b0;
            end
            out_ready = 1'b1;

            wait (out_valid && out_ready);
            @(posedge clk);
            out_ready = 1'b0;
        end
    endtask

    initial begin
        rst_n         = 1'b0;
        in_valid      = 1'b0;
        in_last       = 1'b0;
        out_ready     = 1'b0;
        key           = {KEY_BITS{1'b0}};
        plaintext     = 128'h0;
        last_check_ok = 1'b1;

        repeat (3) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        $display("---------------------------------------------------------------");
        $display("KEY_BITS  = %0d", KEY_BITS);
        $display("plaintext = %h", PLAINTEXT_VEC);
        $display("---------------------------------------------------------------");

        // Block 1: in_last=0 -- same known-answer plaintext, not the final
        // block of the (imaginary) message.
        run_one_block(1'b0, PLAINTEXT_VEC);
        if (ciphertext !== EXPECTED_CIPHERTEXT) begin
            $display("FAIL (block1): got %h, expected %h", ciphertext, EXPECTED_CIPHERTEXT);
        end else begin
            $display("PASS (block1): ciphertext = %h, out_last = %b (expected 0)", ciphertext, out_last);
        end

        // Block 2: in_last=1 -- reuses the same plaintext/key so the
        // expected ciphertext is unchanged; only exercises that out_last
        // correctly follows to 1 for this transfer.
        run_one_block(1'b1, PLAINTEXT_VEC);
        if (ciphertext !== EXPECTED_CIPHERTEXT) begin
            $display("FAIL (block2): got %h, expected %h", ciphertext, EXPECTED_CIPHERTEXT);
        end else begin
            $display("PASS (block2): ciphertext = %h, out_last = %b (expected 1)", ciphertext, out_last);
        end

        $display("---------------------------------------------------------------");
        if (last_check_ok) begin
            $display("PASS: out_last tracked in_last correctly on both blocks");
        end else begin
            $display("FAIL: out_last mismatch somewhere above");
        end

        #20 $finish;
    end

endmodule