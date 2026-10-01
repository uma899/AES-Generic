// aes_core_otf.v -- AES encryption core using the on-the-fly
// (iterative) key schedule instead of the fully-parallel one.

module aes_core_otf #(
    parameter KEY_BITS = 256   // 128, 192, or 256
) (
    input  wire                clk,
    input  wire                rst_n,      // active-low async reset

    // ---- input handshake ----
    input  wire                in_valid,
    output wire                in_ready,
    input  wire [KEY_BITS-1:0] key,
    input  wire [127:0]        plaintext,

    // ---- output handshake ----
    output wire                out_valid,
    input  wire                out_ready,
    output reg  [127:0]        ciphertext
);

    // ---------------- Derived parameters ----------------
    localparam integer NK = KEY_BITS / 32;                          // 4, 6, 8
    localparam integer NR = (KEY_BITS == 128) ? 10 :
                             (KEY_BITS == 192) ? 12 : 14;            // 10,12,14

    initial begin
        if (KEY_BITS != 128 && KEY_BITS != 192 && KEY_BITS != 256) begin
            $display("ERROR: aes_core_otf KEY_BITS must be 128, 192, or 256 (got %0d)", KEY_BITS);
            $finish;
        end else $display("key bits %0d - aes_core_otf", KEY_BITS);
    end

    // ---------------- FSM states ----------------
    localparam S_IDLE  = 3'd0,   // in_ready=1, waiting for input transfer
               S_LOAD  = 3'd1,   // round key 0 now valid; do initial AddRoundKey
               S_ROUND = 3'd2,   // rounds 1..NR-1
               S_FINAL = 3'd3,   // round NR (no MixColumns)
               S_OUT   = 3'd4;   // out_valid=1, waiting for output transfer

    reg [2:0]           state;
    reg [127:0]         plaintext_reg;
    reg [127:0]         data_reg;
    reg [4:0]           round_cnt;   // 1..NR

    assign in_ready  = (state == S_IDLE);
    assign out_valid = (state == S_OUT);

    // ---------------- On-the-fly key schedule ----------------
    // Combinational control -- see header note on why these must NOT be
    // registered.
    wire key_exp_load = (state == S_IDLE) && in_valid;
    wire key_exp_next = (state == S_LOAD) || (state == S_ROUND);

    wire [127:0] round_key;   // valid for round round_key_rk_idx, one cycle after load/next
    wire [4:0]   round_key_rk_idx;

    key_expansion_otf #(
        .NK (NK),
        .NR (NR)
    ) u_key_exp (
        .clk       (clk),
        .rst_n     (rst_n),
        .load      (key_exp_load),
        .next      (key_exp_next),
        .key       (key),              // sampled by key_expansion_otf only on its own `load` pulse
        .round_key (round_key),
        .rk_idx    (round_key_rk_idx)
    );

    // ---------------- Combinational round datapath ----------------
    wire [127:0] sb_out, sr_out, mc_out, ark_out_round, ark_out_final;

    sub_bytes    u_sb  (.state_in(data_reg), .state_out(sb_out));
    shift_rows   u_sr  (.state_in(sb_out),   .state_out(sr_out));
    mix_columns  u_mc  (.state_in(sr_out),   .state_out(mc_out));
    add_round_key u_ark_round (.state_in(mc_out), .round_key(round_key), .state_out(ark_out_round));
    add_round_key u_ark_final (.state_in(sr_out), .round_key(round_key), .state_out(ark_out_final));

    // ---------------- FSM ----------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            plaintext_reg <= 128'h0;
            data_reg      <= 128'h0;
            round_cnt     <= 5'd0;
            ciphertext    <= 128'h0;
        end else begin
            case (state)
                // Accept a new {key, plaintext} transfer. key_exp_load is
                // already high (combinationally) this cycle, so round key
                // 0 will be valid starting next cycle (S_LOAD).
                S_IDLE: begin
                    if (in_valid) begin   // in_ready is 1 whenever state==S_IDLE
                        plaintext_reg <= plaintext;
                        state         <= S_LOAD;
                    end
                end

                // round_key now holds round key 0 (key_exp_next is already
                // high this cycle too, so round key 1 will be ready for
                // the first S_ROUND cycle).
                S_LOAD: begin
                    data_reg  <= plaintext_reg ^ round_key;
                    round_cnt <= 5'd1;
                    state     <= S_ROUND;
                end

                // Rounds 1..(NR-1): round_key already holds round key
                // [round_cnt]. key_exp_next is high this whole state, so
                // the following round key is always ready one cycle ahead.
                S_ROUND: begin
                    data_reg <= ark_out_round;
                    if (round_cnt == (NR - 1)) begin
                        round_cnt <= NR;
                        state     <= S_FINAL;
                    end else begin
                        round_cnt <= round_cnt + 5'd1;
                    end
                end

                // Round NR (final): round_key holds round key NR.
                // SubBytes -> ShiftRows -> AddRoundKey (no MixColumns).
                S_FINAL: begin
                    data_reg   <= ark_out_final;
                    ciphertext <= ark_out_final;
                    state      <= S_OUT;
                end

                // Hold ciphertext stable until the consumer accepts it.
                S_OUT: begin
                    if (out_valid && out_ready) begin
                        state <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
