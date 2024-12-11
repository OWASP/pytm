from pytm import Dataflow as DF
from pytm import Element


def req_reply(src: Element, dest: Element, req_name: str, reply_name=None) -> (DF, DF):
    '''
    This function creates two datflows where one dataflow is a request
    and the second dataflow is the corresponding reply to the newly created request.

    Args:
        req_name: name of the request dataflow
        reply_name: name of the reply datadlow
                    if not set the name will be "Reply to <name>"

    Usage:
        query_titles, reply_titles = req_reply(api, database, 'Query book titles')

        view_authors, reply_authors = req_reply(api, database,
                                                req_name='Query authors view',
                                                reply_name='Authors, with top titles')

    Returns:
        a tuple of two dataflows, where the first is the request and the second is the reply.

    '''
    if not reply_name:
        reply_name = f'Reply to {req_name}'
    req = DF(src, dest, req_name)
    reply = DF(dest, src, name=reply_name)
    reply.responseTo = req
    return req, reply


def reply(req: DF, **kwargs) -> DF:
    '''
    This function takes a dataflow as an argument and returns a new dataflow, which is a response to the given dataflow.

    Args:
        req: a dataflow for which a reply should be generated
        kwargs: key word arguments for the newly created reply
    Usage:
        client_query = Dataflow(client, api, "Get authors page")
        api_query = Dataflow(api, database, 'Get authors')
        api_reply = reply(api_query)
        client_reply = reply(client_query)
    Returns:
        a Dataflow which is a reply to the given datadlow req
    '''
    if 'name' not in kwargs:
        name = f'Reply to {req.name}'
    else:
        name = kwargs['name']
        del kwargs['name']
    reply = DF(req.sink, req.source, name, **kwargs)
    reply.responseTo = req
    return req, reply
