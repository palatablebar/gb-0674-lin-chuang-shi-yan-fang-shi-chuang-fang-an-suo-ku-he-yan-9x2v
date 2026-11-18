from app.credential import build
from app.errors import BusinessError


def serialize(result):
    """下载即封存：返回同一业务内容可复现的凭证 ZIP。"""
    if not result.get('manifest') or not result.get('views'):
        raise BusinessError('INCOMPLETE_RUN', '批次尚未完成')
    return build(result)['zip']
