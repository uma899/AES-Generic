# 1. Close active simulation gracefully
catch {quit -sim}

# 2. Re-create work library cleanly
if {[file exists work]} {
    puts "Cleaning up existing 'work' library..."
    file delete -force work
}
vlib work
vmap work work

# 3. Compile SystemVerilog / Verilog files
puts "Compiling ALL Verilog design files and testbench..."
if {[catch {
    vlog -sv -mfcu \
        aes_core_tb.v \
        aes_core.v \
        mix_columns.v \
        sbox.v \
        sub_bytes.v \
        add_round_key.v \
        shift_rows.v \
        key_expansion.v
} result]} {
    puts "COMPILATION FAILED: $result"
    return
}

puts "Compilation completed successfully."

# 4. Elaborate and Start Simulation
puts "Starting simulation of work.aes_core_tb..."
vsim -novopt work.aes_core_tb   ;# Note: Use -voptargs=+acc if on newer Questa Sim

# 5. Add Waves (Optional - uncomment if running in GUI)
# add wave -r /*

# 6. Run Simulation
puts "Running simulation..."
run 300 ns