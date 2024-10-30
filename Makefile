all:
	docker build -t load-and-profile .

run:
	docker run -it --rm --network=none \
		-v"/Volumes/NO NAME/crypter70/IndoBERT-Sentiment-Analysis":/IndoBERT-Sentiment-Analysis \
		-v.:/output/ \
		load-and-profile /IndoBERT-Sentiment-Analysis
