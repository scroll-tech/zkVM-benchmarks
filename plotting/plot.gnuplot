# plot_sp1_ceno.gnu

# 1) Choose SVG output
set terminal svg size 800,600 font "Helvetica,10"
set output 'sp1_ceno_scatter.svg'

# 2) Basic plot settings
set title "Scatterplot of sp1 vs ceno"
set key left box
set grid
set xlabel "n"
set ylabel "time (s)"

# 3) Plot: sp1 and ceno from the same data file 
plot "sp1.data" using 1:3 \
     with points title "sp1", \
     "ceno.data"          using 1:3 \
     with points title "ceno"

# 4) Close the output
set output
