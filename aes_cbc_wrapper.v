module aes_cbc_wrapper #(
    parameter KEY_BITS = 256   // 128, 192, or 256
) (
    input  wire                clk,
    input  wire                rst_n,
    input  wire                init,
    input  wire [127:0]        iv,         // Initialization Vector (128-bit)

    input  wire                in_valid,
    output wire                in_ready,
    input  wire [KEY_BITS-1:0] key,
    input  wire [127:0]        plaintext,

    output wire                out_valid,
    input  wire                out_ready,
    output wire [127:0]        ciphertext
);

    // Internal chaining register for storing the feedback vector (IV or previous Ciphertext)
    reg [127:0] chain_reg;

    // Zero-latency select: Use 'iv' directly when 'init' is asserted, else use stored 'chain_reg'
    wire [127:0] feedback_vector = init ? iv : chain_reg;
    wire [127:0] core_plaintext  = plaintext ^ feedback_vector;

    // Instantiate underlying AES core
    aes_core_otf #(
        .KEY_BITS(KEY_BITS)
    ) u_aes_core (
        .clk        (clk),
        .rst_n      (rst_n),
        .in_valid   (in_valid),
        .in_ready   (in_ready),
        .key        (key),
        .plaintext  (core_plaintext),
        .out_valid  (out_valid),
        .out_ready  (out_ready),
        .ciphertext (ciphertext)
    );

    // CBC feedback state update logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            chain_reg <= 128'h0;
        end else if (init) begin
            chain_reg <= iv;
        end else if (out_valid && out_ready) begin
            chain_reg <= ciphertext;
        end
    end

endmodule