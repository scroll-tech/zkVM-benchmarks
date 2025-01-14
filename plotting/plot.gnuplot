# plot_sp1_ceno.gnu

# 1) Choose SVG output
set terminal png size 1600,1200 font "Helvetica,10"
set output 'sp1_ceno_scatter.png'

# 2) Basic plot settings
set title "Scatterplot of sp1 vs ceno for sorting a vector"
set key left box
set grid
set xlabel "input length"
set ylabel "time to prove sorting (s)"

# =========== DEFINE FUNCTIONS FOR FIT ===========
# We'll fit each data set separately to its own line.
f_sp1(x) = a_sp1*x + b_sp1
f_ceno(x) = a_ceno*x + b_ceno

# =========== DO THE FITS ===========

# Fit sp1 data
fit f_sp1(x) "sp1.data" using 1:3 via a_sp1, b_sp1

# Fit ceno data
fit f_ceno(x) "ceno.data" using 1:3 via a_ceno, b_ceno

# 3) Plot: sp1 and ceno from the same data file 
plot "sp1.data" using 1:3 \
     with points title "SP1 with AVX512", \
     f_sp1(x) title sprintf("sp1 fit: y=%.5fx+%.3f", a_sp1, b_sp1) lw 2, \
     "ceno.data"          using 1:3 \
     with points title "Ceno", \
     f_ceno(x) title sprintf("ceno fit: y=%.5fx+%.3f", a_ceno, b_ceno) lw 2

# 4) Close the output
set output
