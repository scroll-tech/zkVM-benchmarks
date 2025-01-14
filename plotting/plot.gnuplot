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

# 3) Plot: sp1 and ceno from the same data file 
plot "sp1.data" using 1:3 \
     with points title "SP1 with AVX512", \
     "ceno.data"          using 1:3 \
     with points title "Ceno"

# 4) Close the output
set output
