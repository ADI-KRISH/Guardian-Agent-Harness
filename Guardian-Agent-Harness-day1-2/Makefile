.PHONY: run test eval demo
run:
	python3 -m guardian serve
test:
	python3 -m unittest discover -s tests -v
eval:
	python3 -m guardian eval
demo:
	python3 -m guardian scan examples/demo --planted --output .guardian/demo-report.json
