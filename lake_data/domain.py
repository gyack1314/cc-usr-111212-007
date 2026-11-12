"""检查目录列号和策略等级，不编译查询。"""
from .io import unique

def summarize(v,root):
    unique(v['catalog'],'name')
    for table in v['catalog']:
        ids=[x['id'] for x in table['columns']]
        if len(ids)!=len(set(ids)):raise ValueError('字段ID重复')
    for policy in v['policies']:
        if any(x not in ('visible','masked','forbidden') for x in policy['columns'].values()):raise ValueError('列权限未知')
    return {'tables':len(v['catalog']),'policies':len(v['policies']),'queries':len(v['queries'])}
