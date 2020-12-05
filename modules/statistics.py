

class Statistics:
	def __init__(self):
		self.results = []
		self.loss_amount = 0
		self.min_resp_time = 0
		self.average_resp_time = 0
		self.max_res_time = 0

	def update(self, result):
		self.results.append(result)
		