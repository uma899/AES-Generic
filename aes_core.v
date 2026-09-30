// key, plaintext are LATCHED internally - change it. May latch values in mode wrapper and drive this core. And output is also held in reg.

module aes_core #(
    parameter KEY_BITS = 256   // 128, 192, or 256
) (
    input  wire                clk,
    input  wire                rst_n,      // active-low async reset

    // ---- input handshake ----
    input  wire                in_valid,
    output wire                in_ready,
    input  wire [KEY_BITS-1:0] key,
    input  wire [127:0]        plaintext,
 //   input  wire                in_last,    // put this and out_last in outside wrapper that too if this is used for many blocks of data

    // ---- output handshake ----
    output wire                out_valid,
    input  wire                out_ready,
    output reg  [127:0]        ciphertext
  //  output reg                 out_last
);

    // ---------------- Derived parameters ----------------
    localparam integer NK = KEY_BITS / 32;                          // 4, 6, 8
    localparam integer NR = (KEY_BITS == 128) ? 10 :
                             (KEY_BITS == 192) ? 12 : 14;            // 10,12,14
    localparam integer RK_WIDTH = 128 * (NR + 1);

    initial begin
        if (KEY_BITS != 128 && KEY_BITS != 192 && KEY_BITS != 256) begin
            $display("ERROR: aes_core KEY_BITS must be 128, 192, or 256 (got %0d)", KEY_BITS);
            $finish;
        end
    end

    // ---------------- FSM states ----------------
    localparam S_IDLE  = 3'd0,
               S_LOAD  = 3'd1,
               S_ROUND = 3'd2,
               S_FINAL = 3'd3,
               S_OUT   = 3'd4;

    reg [2:0]           state;
    reg [KEY_BITS-1:0]  key_reg;
    reg [127:0]         plaintext_reg;
//    reg                 last_reg;    // in_last, latched alongside plaintext
    reg [127:0]         data_reg;
    reg [4:0]           round_cnt;   // 1..NR

    assign in_ready  = (state == S_IDLE);
    assign out_valid = (state == S_OUT);

    wire [RK_WIDTH-1:0] round_keys_flat;
    key_expansion #(
        .NK (NK),
        .NR (NR)
    ) u_key_exp (
        .key             (key_reg),
        .round_keys_flat (round_keys_flat)
    );

    wire [127:0] rk0  = round_keys_flat[RK_WIDTH-1 -  0*128 -: 128];    // -: 128 Starting at the calculated Base Index, select 128 bits counting downwards.
    wire [127:0] rk_n = round_keys_flat[RK_WIDTH-1 - round_cnt*128 -: 128];

    wire [127:0] sb_out, sr_out, mc_out, ark_out_round, ark_out_final;

    sub_bytes    u_sb  (.state_in(data_reg), .state_out(sb_out));
    shift_rows   u_sr  (.state_in(sb_out),   .state_out(sr_out));
    mix_columns  u_mc  (.state_in(sr_out),   .state_out(mc_out));
    add_round_key u_ark_round (.state_in(mc_out), .round_key(rk_n), .state_out(ark_out_round));
    add_round_key u_ark_final (.state_in(sr_out), .round_key(rk_n), .state_out(ark_out_final));

    // ---------------- FSM ----------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            key_reg       <= {KEY_BITS{1'b0}};
            plaintext_reg <= 128'h0;
//            last_reg      <= 1'b0;
            data_reg      <= 128'h0;
            round_cnt     <= 5'd0;
            ciphertext    <= 128'h0;
//            out_last      <= 1'b0;
        end else begin
            case (state)
                
                S_IDLE: begin
                    if (in_valid) begin   // in_ready is 1 whenever state==S_IDLE
                        key_reg       <= key;
                        plaintext_reg <= plaintext;
//                        last_reg      <= in_last;
                        state         <= S_LOAD;
                    end
                end

                // key_reg is now valid; round-key-0 is available combinationally.
                S_LOAD: begin
                    data_reg  <= plaintext_reg ^ rk0;   // initial AddRoundKey
                    round_cnt <= 5'd1;
                    state     <= S_ROUND;
                end

                // Rounds 1..(NR-1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
                S_ROUND: begin
                    data_reg <= ark_out_round;
                    if (round_cnt == (NR - 1)) begin
                        round_cnt <= NR;
                        state     <= S_FINAL;
                    end else begin
                        round_cnt <= round_cnt + 5'd1;
                    end
                end

                // Round NR (final): SubBytes -> ShiftRows -> AddRoundKey (no MixColumns)
                S_FINAL: begin
                    data_reg   <= ark_out_final;
                    ciphertext <= ark_out_final;
//                    out_last   <= last_reg;   // carry the flag to the matching output
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