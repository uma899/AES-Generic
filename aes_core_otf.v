// aes_core_otf.v -- AES encryption core, on-the-fly key schedule,
// RUN-TIME selectable key size.
//
// key_mode: 2'b00 = AES-128, 2'b01 = AES-192, 2'b10 = AES-256
//           (2'b11 reserved, behaves as AES-256)
// key_mode and key are sampled on the in_valid && in_ready cycle.
// key is MSB-aligned: AES-128 uses key[255:128], AES-192 uses key[255:64].

module aes_core_otf (
    input  wire                clk,
    input  wire                rst_n,      // active-low async reset

    // ---- input handshake ----
    input  wire                in_valid,
    output wire                in_ready,
    input  wire [1:0]          key_mode,
    input  wire [255:0]        key,
    input  wire [127:0]        plaintext,

    // ---- output handshake ----
    output wire                out_valid,
    input  wire                out_ready,
    output reg  [127:0]        ciphertext
);

    // ---------------- FSM states ----------------
    localparam S_IDLE  = 3'd0,
               S_LOAD  = 3'd1,
               S_ROUND = 3'd2,
               S_FINAL = 3'd3,
               S_OUT   = 3'd4;

    reg [2:0]   state;
    reg [127:0] plaintext_reg;
    reg [127:0] data_reg;
    reg [4:0]   round_cnt;   // 1..NR
    reg [4:0]   nr_reg;      // 10 / 12 / 14, latched at accept

    // NR decode of the incoming mode (used only on the accept cycle)
    wire [4:0] nr_in = (key_mode == 2'b00) ? 5'd10 :
                       (key_mode == 2'b01) ? 5'd12 : 5'd14;

    assign in_ready  = (state == S_IDLE);
    assign out_valid = (state == S_OUT);

    // ---------------- On-the-fly key schedule ----------------
    wire key_exp_load = (state == S_IDLE) && in_valid;
    wire key_exp_next = (state == S_LOAD) || (state == S_ROUND);

    wire [127:0] round_key;
    wire [4:0]   round_key_rk_idx;

    key_expansion_otf u_key_exp (
        .clk       (clk),
        .rst_n     (rst_n),
        .load      (key_exp_load),
        .next      (key_exp_next),
        .key_mode  (key_mode),
        .key       (key),
        .round_key (round_key),
        .rk_idx    (round_key_rk_idx)
    );

    // ---------------- Combinational round datapath ----------------
    wire [127:0] sb_out, sr_out, mc_out, ark_out_round, ark_out_final;

    sub_bytes     u_sb  (.state_in(data_reg), .state_out(sb_out));
    shift_rows    u_sr  (.state_in(sb_out),   .state_out(sr_out));
    mix_columns   u_mc  (.state_in(sr_out),   .state_out(mc_out));
    add_round_key u_ark_round (.state_in(mc_out), .round_key(round_key), .state_out(ark_out_round));
    add_round_key u_ark_final (.state_in(sr_out), .round_key(round_key), .state_out(ark_out_final));

    // ---------------- FSM ----------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            plaintext_reg <= 128'h0;
            data_reg      <= 128'h0;
            round_cnt     <= 5'd0;
            nr_reg        <= 5'd14;
            ciphertext    <= 128'h0;
        end else begin
            case (state)
                S_IDLE: begin
                    if (in_valid) begin
                        plaintext_reg <= plaintext;
                        nr_reg        <= nr_in;
                        state         <= S_LOAD;
                    end
                end

                S_LOAD: begin
                    data_reg  <= plaintext_reg ^ round_key;
                    round_cnt <= 5'd1;
                    state     <= S_ROUND;
                end

                S_ROUND: begin
                    data_reg <= ark_out_round;
                    if (round_cnt == (nr_reg - 5'd1)) begin
                        round_cnt <= nr_reg;
                        state     <= S_FINAL;
                    end else begin
                        round_cnt <= round_cnt + 5'd1;
                    end
                end

                S_FINAL: begin
                    data_reg   <= ark_out_final;
                    ciphertext <= ark_out_final;
                    state      <= S_OUT;
                end

                S_OUT: begin
                    if (out_valid && out_ready)
                        state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
