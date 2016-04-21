### 
###  Created on: 09 July 2015
###  Author: Mohammed Al-Khalidi <mshawk@essex.ac.uk> 
### 


library(graph)
library(igraph)

g <- barabasi.game(5, directed = FALSE)
g <- as_graphnel(g)

ed <- list()
XX <- list()
YY <- list()
edgenum=0;
for(i in nodes(g)) {
    for(el in graph::edges(g)[[i]]) {
        ed <- c(ed,list(c(i,el)))
        XX <-  c(XX,list(i))
        YY <- c(YY,list(el))
edgenum <- edgenum + 1 ;
    }
}
X <- as.numeric(XX)
Y <- as.numeric(YY)


n=edgenum;

z <- nchar(X)
p <- nchar(Y)

h=1;

for(i in seq(1:h)) 
 
{ 
cat(file="ns_topology.cfg", append=FALSE, "BLACKADDER_ID_LENGTH = 8;")
cat(file="ns_topology.cfg", append=TRUE, "\nLIPSIN_ID_LENGTH = 32;")
cat(file="ns_topology.cfg", append=TRUE, "\nWRITE_CONF = ")
cat(file="ns_topology.cfg", append=TRUE, "\"/tmp/\";")
cat(file="ns_topology.cfg", append=TRUE, "\n\nnetwork = {")
cat(file="ns_topology.cfg", append=TRUE, "\nnodes = (")

}
v=1;
for(i in seq(1:n)) 
 
{ 

 if ((X[i] == v) && ( v==1 ))
{

	


cat(file="ns_topology.cfg", append=TRUE, "\n{")

cat(file="ns_topology.cfg", append=TRUE, "\nrole = [];")


b=z[i];
w=p[i];

if(b == 1) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")

}
if (b == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"000000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")

}
if (b == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"00000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")

}		
cat(file="ns_topology.cfg", append=TRUE, "\n{")
 
if(w == 1) {               
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")

}
if (w == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")

}
if (w == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"00000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")

}
cat(file="ns_topology.cfg", append=TRUE, "\nDataRate =")
cat(file="ns_topology.cfg", append=TRUE, "\"100Mbps\"")
cat(file="ns_topology.cfg", append=TRUE, ";")

cat(file="ns_topology.cfg", append=TRUE, "\nDelay = \"10ms\";")

if (X[i+1]== v)

{
cat(file="ns_topology.cfg", append=TRUE, "\n},")
 }
else 
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")
} 
      
i <- i+1
	v <- v+1	
}


		
else if (X[i] == 1)

{
  w=p[i];
  cat(file="ns_topology.cfg", append=TRUE, "\n{")
 
if(w == 1) {    
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
if (w == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
if (w == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"00000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")
cat(file="ns_topology.cfg", append=TRUE, "\nDataRate =")

cat(file="ns_topology.cfg", append=TRUE, "\"100Mbps\"")
cat(file="ns_topology.cfg", append=TRUE, ";")
cat(file="ns_topology.cfg", append=TRUE, "\nDelay = \"10ms\";")
if(X[i + 1] == 1)


{
cat(file="ns_topology.cfg", append=TRUE, "\n},")
 
}
else if(X[i + 1] != 1) 
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")

}     

i <- i+1

}


}


m =2;

for(i in seq(1:n)) 
 
{ 


 if (X[i] == m)
{

	
cat(file="ns_topology.cfg", append=TRUE, "\n);")
	
cat(file="ns_topology.cfg", append=TRUE, "\n},")

cat(file="ns_topology.cfg", append=TRUE, "\n{")

cat(file="ns_topology.cfg", append=TRUE, "\nrole = [];")


b=z[i];
w=p[i];
{
if(b == 1) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")

}
if (b == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"000000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")

}
if (b == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nlabel =","\"00000")
cat(file="ns_topology.cfg", append=TRUE, X[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

cat(file="ns_topology.cfg", append=TRUE, "\nconnections = (")
	
}		
cat(file="ns_topology.cfg", append=TRUE, "\n{")
 
if(w == 1) {               
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
if (w == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

}
if (w == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"00000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}

cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")
cat(file="ns_topology.cfg", append=TRUE, "\nDataRate =")
cat(file="ns_topology.cfg", append=TRUE, "\"100Mbps\"")
cat(file="ns_topology.cfg", append=TRUE, ";")

cat(file="ns_topology.cfg", append=TRUE, "\nDelay = \"10ms\";")


if ((i+1) <= n)
{

if (X[i + 1] == m)  


{
cat(file="ns_topology.cfg", append=TRUE, "\n},")
 
}
else if (X[i + 1] != m )
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")

} 
}
 else if ((i+1) > n)
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")

}

      
i <- i+1
	m <- m+1	
}


}		
else if ((X[i] == (m -1)) && (X[i] != 1))

{
  w=p[i];
  cat(file="ns_topology.cfg", append=TRUE, "\n{")
 
if(w == 1) {    
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"0000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
if (w == 2) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"000000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")
}
if (w == 3) {
cat(file="ns_topology.cfg", append=TRUE, "\nto = ","\"00000")
cat(file="ns_topology.cfg", append=TRUE, Y[i])
cat(file="ns_topology.cfg", append=TRUE, "\";")

}
cat(file="ns_topology.cfg", append=TRUE, "\nMtu = 1500;")
cat(file="ns_topology.cfg", append=TRUE, "\nDataRate =")

cat(file="ns_topology.cfg", append=TRUE, "\"100Mbps\"")
cat(file="ns_topology.cfg", append=TRUE, ";")
cat(file="ns_topology.cfg", append=TRUE, "\nDelay = \"10ms\";")


if ((i+1) <= n)
{
if(X[i + 1] == (m -1))


{
cat(file="ns_topology.cfg", append=TRUE, "\n},")
 
}
else if(X[i + 1] != (m -1)) 
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")

}
}
 else if ((i+1) > n)
{
cat(file="ns_topology.cfg", append=TRUE, "\n}")

}
 
       

i <- i+1

}
}


cat(file="ns_topology.cfg", append=TRUE, "\n);")
	
cat(file="ns_topology.cfg", append=TRUE, "\n}")
cat(file="ns_topology.cfg", append=TRUE, "\n);")
	
cat(file="ns_topology.cfg", append=TRUE, "\n};")

