"""Reference math for offline studies, never imported by the production brain."""
import math
from functools import lru_cache


class MissingData(ValueError):
    pass


def number(value, name, low=0, high=1e12):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError('%s must be a finite number in [%s, %s]' % (name, low, high))
    return value


def required(obj, name):
    if name not in obj or obj[name] is None:
        raise MissingData('missing ' + name)
    return obj[name]


def binomial_cdf(n, p, x):
    if p <= 0:
        return 1.0
    if p >= 1:
        return float(x >= n)
    return min(1.0, math.fsum(math.exp(math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1)
                                      + k*math.log(p)+(n-k)*math.log1p(-p)) for k in range(x+1)))


@lru_cache(maxsize=201)
def confidence_rank(n):
    cumulative = 0.0
    for k in range(n):
        cumulative += math.exp(math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1)
                               + k*math.log(.9)+(n-k)*math.log(.1))
        if cumulative >= .95:
            return k+1
    return None


@lru_cache(maxsize=4096)
def failure_bound(n, overdue):
    if not n or overdue == n:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(60):
        p = (lo+hi)/2
        if binomial_cdf(n, p, overdue) > .05:
            lo = p
        else:
            hi = p
    return hi


def duration_estimate(samples, prior, overdue):
    """281 order-statistic bound and one-sided 95% Clopper-Pearson bound.

    None denotes a right-censored sample, not a zero duration. Inputs are already
    filtered to the correct workload/action/window by the trace producer.
    """
    n = len(samples)
    values = sorted(float('inf') if v is None else v for v in samples)
    mid = prior if n < 29 else (values[(n-1)//2]+values[n//2])/2
    if n < 29:
        upper = max([prior] + values)
    else:
        rank = confidence_rank(n)
        upper = values[rank-1] if rank is not None else float('inf')
    return mid, upper, failure_bound(n, overdue)


def price(candidate, config, budget):
    data = candidate.get('cost', {})
    kind = config['kind']
    if kind == 'provided':
        return {'c': required(data, 'c'), 'rho': required(data, 'rho'), 'unit': 'endpoint-seconds'}
    if kind == 'legacy':
        norm, flow = required(data, 'norm'), required(data, 'flow')
        return {'c': config['norm_weight']*norm+config['flow_weight']*flow,
                'rho': None, 'norm': norm, 'flow': flow, 'chi': required(data, 'chi'),
                'unit': 'dimensionless'}
    priors = {'stateless': 43, 'gpu': 130, 'stateful': 141, 'unknown': 400}
    prior = priors[required(data, 'class')]
    k = required(data, 'k')
    samples = required(data, 'samples')
    overdue = required(data, 'overdue')
    mid, upper, pf = duration_estimate(samples, prior, overdue)
    result = {'unit': 'endpoint-seconds', 'sample_count': len(samples), 't_mid': mid,
              't_upper': upper, 'p_f': pf, 'rollback_estimator': 'STAND_IN'}
    # No removed endpoints: do not evaluate 0*infinity.
    if k == 0:
        return {**result, 'c': 0, 'rho': 0, 'flow': 0, 'norm': 0}
    if not math.isfinite(upper):
        return {**result, 'c': None, 'rho': None, 'refusal': 'BOUND_MISSING'}
    delta = config['delta']
    duration = upper
    if candidate['action'] == 'quarantine':
        # Samples for quarantine must describe the closing rotate, not the hold.
        if required(data, 'sample_action') != 'rotate':
            raise MissingData('quarantine requires closing-rotate samples')
        if k != 1:
            raise ValueError('quarantine k must be 0 (no endpoints) or 1')
        left = remaining(budget)
        hold = min(required(data, 'hold_cap'), left-delta-3*upper)
        if hold <= 0:
            return {**result, 'c': None, 'rho': None, 'refusal': 'BUDGET'}
        duration, mid = hold+upper, hold+mid
        result.update(hold=hold, t_mid=mid)
    rho = k*(duration+delta+upper)+k*upper
    flow = k*mid
    norm = pf*(k*(duration-mid+delta+upper)+k*upper)
    return {**result, 'c': flow+norm, 'rho': rho, 'flow': flow, 'norm': norm}


def remaining(budget):
    if budget is None:
        raise MissingData('missing authoritative budget (r, used, held); zero is not inferred')
    return required(budget, 'r')-required(budget, 'used')-required(budget, 'held')


def weighted(scores, weights, scale):
    best = max(scores)
    logs = [math.log(w)+(j-best)/scale for j, w in zip(scores, weights)]
    shift = max(logs)
    terms = [math.exp(v-shift) for v in logs]
    total = math.fsum(terms)
    return [v/total for v in terms]


def distribution(scores, config, weights=None):
    """Return p and diagnostics. Ordering of candidates must be stable upstream."""
    if not scores:
        return [], {'expected_regret': 0}
    best = max(scores)
    kind = config['kind']
    if kind == 'deterministic':
        return [float(i == scores.index(best)) for i in range(len(scores))], {'expected_regret': 0}
    weights = weights or [1.0]*len(scores)
    top_total = math.fsum(w for j, w in zip(scores, weights) if j == best)
    star = [w/top_total if j == best else 0 for j, w in zip(scores, weights)]
    epsilon = config['epsilon']
    if epsilon == 0:
        return star, {'expected_regret': 0, 'alpha': 0 if kind == 'history' else None,
                      'temperature': 0 if kind == 'entropy' else None, 'r_star': star}
    if kind == 'history':
        q = weighted(scores, weights, config['score_scale'])
        loss = math.fsum(p*(best-j) for p, j in zip(q, scores))
        alpha = 1 if loss == 0 else min(1.0, epsilon/loss)
        p = [(1-alpha)*r+alpha*v for r, v in zip(star, q)]
        return p, {'q': q, 'r_star': star, 'alpha': alpha,
                   'expected_regret': math.fsum(v*(best-j) for v, j in zip(p, scores))}
    hi, lo = config['tau'], 0.0
    p = weighted(scores, weights, hi)
    if math.fsum(v*(best-j) for v, j in zip(p, scores)) > epsilon:
        # Keep the feasible lower bound, not an infeasible midpoint.
        p = star
        for _ in range(64):
            temp = (hi+lo)/2
            trial = weighted(scores, weights, temp)
            loss = math.fsum(v*(best-j) for v, j in zip(trial, scores))
            if loss <= epsilon:
                lo, p = temp, trial
            else:
                hi = temp
        temp = lo
    else:
        temp = hi
    return p, {'temperature': temp, 'expected_regret': math.fsum(v*(best-j) for v, j in zip(p, scores))}
