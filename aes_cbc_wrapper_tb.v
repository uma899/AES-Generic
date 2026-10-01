// tb_aes_cbc_wrapper.v -- IEEE 1364-2001 Verilog Testbench for aes_cbc_wrapper

`timescale 1ns / 1ps

module aes_cbc_wrapper_tb;

    parameter KEY_BITS   = 128;
    parameter CLK_PERIOD = 10; // 100 MHz clock

    // DUT Signals
    reg                clk;
    reg                rst_n;
    reg                init;
    reg  [127:0]       iv;
    reg                in_valid;
    wire               in_ready;
    reg  [KEY_BITS-1:0] key;
    reg  [127:0]       plaintext;
    wire               out_valid;
    reg                out_ready;
    wire [127:0]       ciphertext;

    // Test Vector Storage
    reg [127:0] PT [0:3];
    reg [127:0] EXPECTED_CT [0:3];
    reg [127:0] nist_key;
    reg [127:0] nist_iv;

    integer error_count;
    integer i;

    // Instantiate DUT
    aes_cbc_wrapper #(
        .KEY_BITS(KEY_BITS)
    ) dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .init       (init),
        .iv         (iv),
        .in_valid   (in_valid),
        .in_ready   (in_ready),
        .key        (key),
        .plaintext  (plaintext),
        .out_valid  (out_valid),
        .out_ready  (out_ready),
        .ciphertext (ciphertext)
    );

    // Clock Generation
    initial begin
        clk = 1'b0;
        forever #(CLK_PERIOD / 2) clk = ~clk;
    end

    // Initialize NIST Test Vectors
    initial begin
        nist_key = 128'h10a58869d74be5a374cf867cfb473859;
        nist_iv  = 128'h00000000000000000000000000000000;

        PT[0] = 128'h00000000000000000000000000000000;
        PT[1] = 128'h00000000000000000000000000000000;
        PT[2] = 128'h30c81c46a35ce411e5fbc1191a0a52ef;              // chnage these. it wont work
        PT[3] = 128'hf69f2445df4f9b17ad2b417be66c3710;

        EXPECTED_CT[0] = 128'h6d251e6944b051e04eaa6fb4dbf78465;
        EXPECTED_CT[1] = 128'hf5d3d58503b9699de785895a96fdbaaf;
        EXPECTED_CT[2] = 128'h43b1cd7f598ece23881b00e3ed030688;
        EXPECTED_CT[3] = 128'h7b0c785e27e8ad3f8223207104725dd4;
    end

    initial begin
        rst_n       = 1'b0;
        in_valid    = 1'b0;
        init        = 1'b0;
        out_ready   = 1'b1;
        key         = 128'b0;
        iv          = 128'b0;
        plaintext   = 128'b0;
        error_count = 0;

        #(CLK_PERIOD * 5);
        rst_n = 1'b1;
        #(CLK_PERIOD * 2);

        $display("\n==========================================");
        $display(" Starting AES-128 CBC NIST Test Routine ");
        $display("==========================================\n");

        for (i = 0; i < 4; i = i + 1) begin
            // 1. Assert input block handshake signals
            @(posedge clk);
            in_valid  <= 1'b1;
            init      <= (i == 0) ? 1'b1 : 1'b0;
            plaintext <= PT[i];
            key       <= nist_key;
            iv        <= nist_iv;

            // 2. Wait until DUT accepts the input block
            @(posedge clk);
            while (!in_ready) begin
                @(posedge clk);
            end

            // Deassert input valid on next cycle after acceptance
            in_valid <= 1'b0;
            init     <= 1'b0;

            // 3. Wait for output valid signal
            while (!out_valid) begin
                @(posedge clk);
            end

            // 4. Verify ciphertext block
            if (ciphertext !== EXPECTED_CT[i]) begin
                $display("[FAIL] Block %0d Mismatch!", i);
                $display("       Expected: %h", EXPECTED_CT[i]);
                $display("       Got:      %h", ciphertext);
                error_count = error_count + 1;
            end else begin
                $display("[PASS] Block %0d Match: %h", i, ciphertext);
            end
        end

        $display("\n==========================================");
        if (error_count == 0) begin
            $display(" TEST PASSED: All 4 CBC blocks matched! ");
        end else begin
            $display(" TEST FAILED: %0d errors detected. ", error_count);
        end
        $display("==========================================\n");

        $finish;
    end

endmodule