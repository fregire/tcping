from .structures import *


class Loss_percent_stat():
	def __init__(self):
		self.res_count = 0
		self.loss_count = 0

	def update(self, result):
		self.res_count += 1
		if result.state is State.ABORTED:
			self.loss_count += 1

	def get_result(self):
		return (self.loss_count / self.res_count) * 100

	def get_formatted_res(self):
		return f'{int(self.get_result())} % loss'

	def __str__(self):
		return "Loss percent"


class Min_time_stat():
	def __init__(self):
		self.min_time = None

	def update(self, result):
		if result.state is State.ABORTED:
			return

		if not self.min_time or self.min_time < result.response_time:
			self.min_time = result.response_time


	def get_formatted_res(self):
		return str(self.min_time)


	def __str__(self):
		return "Min response time"


class Max_time_stat():
	def __init__(self):
		self.max_time = 0

	def update(self, result):
		if result.state is State.ABORTED:
			return

		if self.max_time > result.response_time:
			self.max_time = result.response_time

	def get_formatted_res(self):
		return str(self.max_time)

	def __str__(self):
		return "Max response time"


class Average_stat():
	def __init__(self):
		self.average_time = 0
		self.res_count = 0


	def update(self, result):
		if result.state is State.ABORTED:
			return

		self.average_time = self.average_time * self.res_count + result.response_time


	def get_formatted_res(self):
		return str(self.average_time)


	def __str__(self):
		return "Average response time"


class Stat():
	def __init__(self):
		self.results = []
		self.loss_amount = 0
		self.min_resp_time = 0
		self.average_resp_time = 0
		self.max_res_time = 0
		self.stats = [Loss_percent_stat(), Min_time_stat(), Max_time_stat(), Average_stat()]


	def update(self, result):
		self.results.append(result)

		for stat in self.stats:
			stat.update(result)

	def get_formatted_res(self):
		res = ''

		for stat in self.stats:
			res += f'{stat}: {stat.get_formatted_res()} \n'

		return res
		