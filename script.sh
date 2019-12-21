echo "from: "
read from
echo "to: "
read to
echo "amount: "
read amount
echo "numSend"
read numSend

t=4

for ((i = 0; i<$numSend; i++))
do 
	./blockchain_go.exe send -from $from -to $to -amount $amount
	sleep 20
	if [($i % 10) == 0]
	then
		t=$t+1	
	fi
	
	timeout $t ./blockchain_go.exe startnode
done