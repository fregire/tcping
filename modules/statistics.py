from .structures import State, Result


def get_formatted_time(t):
    return '{:.4f}'.format(t)


class LossPercentStat:
    def __init__(self):
        self.res_count = 0
        self.loss_count = 0

    def update(self, result):
        self.res_count += 1
        if result.state is State.TIMEOUT:
            self.loss_count += 1

    def get_result(self):
        return (self.loss_count / self.res_count) * 100

    def get_formatted_result(self):
        return f'Loss percent: {int(self.get_result())} % loss'


class MinTimeStat:
    def __init__(self):
        self.min_time = None

    def update(self, result):
        if not result.response_time:
            return

        if not self.min_time or result.response_time < self.min_time:
            self.min_time = result.response_time

    def get_formatted_result(self):
        min_time = self.min_time
        if not self.min_time:
            min_time = 0
        return f'Min response time: {get_formatted_time(min_time)}'


class MaxTimeStat:
    def __init__(self):
        self.max_time = None

    def update(self, result):
        if not result.response_time:
            return

        if not self.max_time or result.response_time > self.max_time:
            self.max_time = result.response_time

    def get_formatted_result(self):
        max_time = self.max_time
        if not self.max_time:
            max_time = 0
        return f'Max response time: {get_formatted_time(max_time)}'


class AverageStat:
    def __init__(self):
        self.average_time = 0
        self.res_count = 0

    def update(self, result):
        if not result.response_time:
            return

        self.average_time = (
            self.average_time * self.res_count
            + result.response_time)

    def get_formatted_result(self):
        return f'Average response time: ' \
                f'{get_formatted_time(self.average_time)}'


class Stat:
    def __init__(self):
        self.results = []
        self.stats = [
            LossPercentStat(),
            MinTimeStat(),
            MaxTimeStat(),
            AverageStat()]

    def update(self, result):
        self.results.append(result)

        for stat in self.stats:
            stat.update(result)

    def get_formatted_result(self):
        res = ''

        for stat in self.stats:
            res += f'{stat.get_formatted_result()} \n'

        return res
