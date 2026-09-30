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

    wire                 out_valid;
    reg                  out_ready;
    wire [127:0]         ciphertext;

    // ---- FIPS-197 Appendix C test vectors (same plaintext for all) ----
    localparam [127:0] PLAINTEXT_VEC = 128'h96ab5c2ff612d9dfaae8c31f30c42168;

    localparam [255:0] KEY_128_FULL = 256'h00000000000000000000000000000000;
    localparam [255:0] KEY_192_FULL = 256'h000102030405060708090a0b0c0d0e0f1011121314151617;
    localparam [255:0] KEY_256_FULL = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;

    localparam [255:0] KEY_SEL = (KEY_BITS == 128) ? KEY_128_FULL :
                                  (KEY_BITS == 192) ? KEY_192_FULL :
                                                       KEY_256_FULL;

    localparam [127:0] EXPECTED_CIPHERTEXT =
        (KEY_BITS == 128) ? 128'hff4f8391a6a40ca5b25d23bedd44a597 :
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
        .out_valid  (out_valid),
        .out_ready  (out_ready),
        .ciphertext (ciphertext)
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
            $display("t=%0t | state=%-5s | round=%0d | data_reg=%h | in_v=%b in_r=%b | out_v=%b out_r=%b",
                      $time, state_name(dut.state), dut.round_cnt, dut.data_reg,
                      in_valid, in_ready, out_valid, out_ready);
        end
    end

    // 100 MHz clock
    initial clk = 1'b0;
    always #5 clk = ~clk;

    // Drives one in_valid/in_ready handshake, then holds out_ready low for


    initial begin
        rst_n     = 1'b0;
        in_valid  = 1'b0;
        out_ready = 1'b0;
        key       = {KEY_BITS{1'b0}};
        plaintext = 128'h0;

        repeat (3) @(posedge clk);
        rst_n = 1'b1;                   // since aes core works when reset = 1 - active-low reset
        @(posedge clk);

        $display("---------------------------------------------------------------");
        $display("KEY_BITS  = %0d", KEY_BITS);
        $display("plaintext = %h", PLAINTEXT_VEC);
        $display("---------------------------------------------------------------");

        @(posedge clk);
        in_valid  = 1'b1;
        key       = KEY_SEL[KEY_BITS-1:0];
        plaintext = PLAINTEXT_VEC;

        // wait for the handshake to actually complete
        wait (in_valid && in_ready);
        @(posedge clk);
        in_valid = 1'b0;

        // deliberately stall the output side for a bit
        out_ready = 1'b0;
        wait (out_valid == 1'b1);
        repeat (3) @(posedge clk);   // out_valid must stay high, ciphertext stable
        out_ready = 1'b1;
        
        wait (out_valid && out_ready);
        @(posedge clk);
        out_ready = 1'b0;

        $display("---------------------------------------------------------------");
        if (ciphertext === EXPECTED_CIPHERTEXT) begin
            $display("PASS: ciphertext = %h", ciphertext);
        end else begin
            $display("FAIL: got %h, expected %h", ciphertext, EXPECTED_CIPHERTEXT);
        end

        #20 $finish;
    end

endmodule