// key_expansion_otf.v -- On-the-fly (iterative) AES key schedule,
// RUN-TIME selectable key size.
//
// key_mode (sampled on `load`, then held internally until next `load`):
//     2'b00 = AES-128 (NK=4, NR=10)
//     2'b01 = AES-192 (NK=6, NR=12)
//     2'b10 = AES-256 (NK=8, NR=14)
//     2'b11 = reserved (treated as AES-256)
//
// key is always 256 bits wide and MSB-aligned: word i of the cipher key is
// key[255-32*i -: 32].  AES-128 uses key[255:128], AES-192 uses key[255:64];
// unused low bits are ignored.
//
// One round key per `next` pulse.  The same 4 x 4 sbox bank is reused for
// every mode (16 sboxes total).
//
// NK=6 note: a round key can be 2 leftover words from the previous
// generation step plus 2 new words (see generated_round_key).

module key_expansion_otf (
    input  wire              clk,
    input  wire              rst_n,
    input  wire              load,
    input  wire              next,
    input  wire [1:0]        key_mode,
    input  wire [255:0]      key,
    output reg  [127:0]      round_key,
    output reg  [4:0]        rk_idx
);

    // ---- mode latched at load ----
    reg [1:0] mode_q;
    wire      m256 = mode_q[1];                    // NK=8
    wire      m192 = ~mode_q[1] & mode_q[0];       // NK=6
    wire [3:0] nk  = m256 ? 4'd8 : m192 ? 4'd6 : 4'd4;

    // mode decode for the incoming key (valid in the load cycle)
    wire ld256 = key_mode[1];
    wire ld192 = ~key_mode[1] & key_mode[0];
    wire [3:0] ld_nk = ld256 ? 4'd8 : ld192 ? 4'd6 : 4'd4;

    // ---- helpers ----
    function [31:0] rcon_word;
        input [3:0] idx;
        reg [7:0] rc;
        begin
            case (idx)
                4'd1:  rc = 8'h01; 4'd2:  rc = 8'h02; 4'd3: rc = 8'h04; 4'd4: rc = 8'h08;
                4'd5:  rc = 8'h10; 4'd6:  rc = 8'h20; 4'd7: rc = 8'h40; 4'd8: rc = 8'h80;
                4'd9:  rc = 8'h1b; 4'd10: rc = 8'h36;
                default: rc = 8'h00;
            endcase
            rcon_word = {rc, 24'h000000};
        end
    endfunction

    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:0], w[31:24]};
        end
    endfunction

    // Window of the last NK words, hist[0] = oldest.  Always declared 8 deep.
    reg [31:0] hist [0:7];

    // Position tracking, replaces a modulo/divide on the global word index:
    //   wc     = (index of first word of this step) mod NK
    //   rcon_i = (index of first word of this step) / NK
    reg [3:0] wc;
    reg [3:0] rcon_i;

    // ---- one 4-word generation step (combinational, reused every cycle) ----
    wire [31:0] new_w [0:3];

    // word immediately before the first new word = newest word in the window
    wire [31:0] last_word = m256 ? hist[7] : m192 ? hist[5] : hist[3];

    genvar m;
    generate
        for (m = 0; m < 4; m = m + 1) begin : SUBWORD_UNIT
            localparam [3:0] M = m;

            wire [31:0] prev_word;
            if (m == 0) begin : PW0
                assign prev_word = last_word;
            end else begin : PWN
                assign prev_word = new_w[m-1];
            end

            wire [3:0] sum  = wc + M;
            wire       wrap = (sum >= nk);
            wire [3:0] pos  = wrap ? (sum - nk) : sum;     // (g+m) mod NK

            wire is_rcon = (pos == 4'd0);
            wire is_subw = m256 && (pos == 4'd4);

            wire [31:0] sbox_in = is_rcon ? rot_word(prev_word) : prev_word;
            wire [7:0]  sbox_o0, sbox_o1, sbox_o2, sbox_o3;
            sbox u_sb0 (.in(sbox_in[31:24]), .out(sbox_o0));
            sbox u_sb1 (.in(sbox_in[23:16]), .out(sbox_o1));
            sbox u_sb2 (.in(sbox_in[15:8]),  .out(sbox_o2));
            sbox u_sb3 (.in(sbox_in[7:0]),   .out(sbox_o3));
            wire [31:0] subword_out = {sbox_o0, sbox_o1, sbox_o2, sbox_o3};

            wire [3:0] rc_idx = rcon_i + {3'b000, wrap};   // (g+m) / NK

            wire [31:0] temp = is_rcon ? (subword_out ^ rcon_word(rc_idx)) :
                               is_subw ? subword_out :
                                         prev_word;

            assign new_w[m] = hist[m] ^ temp;
        end
    endgenerate

    // ---- window after this step: drop oldest 4, append the 4 new words ----
    reg [31:0] shifted_hist [0:7];
    always @* begin
        if (m256) begin
            shifted_hist[0] = hist[4];  shifted_hist[1] = hist[5];
            shifted_hist[2] = hist[6];  shifted_hist[3] = hist[7];
            shifted_hist[4] = new_w[0]; shifted_hist[5] = new_w[1];
            shifted_hist[6] = new_w[2]; shifted_hist[7] = new_w[3];
        end else if (m192) begin
            shifted_hist[0] = hist[4];  shifted_hist[1] = hist[5];
            shifted_hist[2] = new_w[0]; shifted_hist[3] = new_w[1];
            shifted_hist[4] = new_w[2]; shifted_hist[5] = new_w[3];
            shifted_hist[6] = 32'h0;    shifted_hist[7] = 32'h0;
        end else begin
            shifted_hist[0] = new_w[0]; shifted_hist[1] = new_w[1];
            shifted_hist[2] = new_w[2]; shifted_hist[3] = new_w[3];
            shifted_hist[4] = 32'h0;    shifted_hist[5] = 32'h0;
            shifted_hist[6] = 32'h0;    shifted_hist[7] = 32'h0;
        end
    end

    // ---- round key once past the free zone ----
    wire [127:0] generated_round_key = m192 ? {hist[4], hist[5], new_w[0], new_w[1]}
                                            : {new_w[0], new_w[1], new_w[2], new_w[3]};

    // ---- wc / rcon_i update for the next step ----
    wire [3:0] wc_sum   = wc + 4'd4;
    wire       wc_wrap  = (wc_sum >= nk);
    wire [3:0] wc_next  = wc_wrap ? (wc_sum - nk) : wc_sum;
    wire [3:0] rcon_nxt = rcon_i + {3'b000, wc_wrap};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mode_q    <= 2'b00;
            rk_idx    <= 5'd0;
            wc        <= 4'd0;
            rcon_i    <= 4'd1;
            round_key <= 128'h0;
            hist[0] <= 32'h0; hist[1] <= 32'h0; hist[2] <= 32'h0; hist[3] <= 32'h0;
            hist[4] <= 32'h0; hist[5] <= 32'h0; hist[6] <= 32'h0; hist[7] <= 32'h0;
        end
        else if (load) begin
            mode_q  <= key_mode;
            hist[0] <= key[255 -: 32];
            hist[1] <= key[223 -: 32];
            hist[2] <= key[191 -: 32];
            hist[3] <= key[159 -: 32];
            hist[4] <= (ld_nk >= 4'd6) ? key[127 -: 32] : 32'h0;
            hist[5] <= (ld_nk >= 4'd6) ? key[95  -: 32] : 32'h0;
            hist[6] <= ld256           ? key[63  -: 32] : 32'h0;
            hist[7] <= ld256           ? key[31  -: 32] : 32'h0;
            wc        <= 4'd0;            // first generated word index == NK -> NK mod NK
            rcon_i    <= 4'd1;            //                                  -> NK / NK
            rk_idx    <= 5'd0;
            round_key <= key[255:128];    // round key 0 = words 0..3, every mode
        end
        else if (next) begin
            if (m256 && rk_idx == 5'd0) begin
                // AES-256 only: round key 1 is words 4..7 of the loaded key.
                rk_idx    <= rk_idx + 5'd1;
                round_key <= {hist[4], hist[5], hist[6], hist[7]};
            end else begin
                hist[0] <= shifted_hist[0]; hist[1] <= shifted_hist[1];
                hist[2] <= shifted_hist[2]; hist[3] <= shifted_hist[3];
                hist[4] <= shifted_hist[4]; hist[5] <= shifted_hist[5];
                hist[6] <= shifted_hist[6]; hist[7] <= shifted_hist[7];
                wc        <= wc_next;
                rcon_i    <= rcon_nxt;
                rk_idx    <= rk_idx + 5'd1;
                round_key <= generated_round_key;
            end
        end
    end

endmodule
