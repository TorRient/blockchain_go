echo "from: "
read from
echo "to: "
read to
echo "amount: "
read amount
echo "numSend"
read numSend

for ((i = 0; i<$numSend; i++))
do 
	./blockchain_go.exe send -from $from -to $to -amount $amount
	sleep 20
	timeout 3s ./blockchain_go.exe startnode
done