#![feature(async_closure)]
#![doc(html_root_url = "https://docs.rs/juniper_hyper/0.2.0")]

#[cfg(test)]
extern crate reqwest;
#[macro_use]
extern crate failure;

use hyper::{
    body::Buf,
    header::{self, HeaderValue},
    Body, Method, Request, Response, StatusCode,
};
use juniper::{
    http::GraphQLRequest as JuniperGraphQLRequest, serde::Deserialize, DefaultScalarValue,
    GraphQLType, InputValue, RootNode, ScalarRefValue, ScalarValue,
};
use std::sync::Arc;
use url::form_urlencoded;

pub async fn graphql<CtxT, QueryT, MutationT, S>(
    root_node: Arc<RootNode<'static, QueryT, MutationT, S>>,
    context: Arc<CtxT>,
    request: Request<Body>,
) -> Result<Response<Body>, hyper::Error>
where
    S: ScalarValue + Send + Sync + 'static,
    for<'b> &'b S: ScalarRefValue<'b>,
    CtxT: Send + Sync + 'static,
    QueryT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    MutationT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    QueryT::TypeInfo: Send + Sync,
    MutationT::TypeInfo: Send + Sync,
{
    match graphql_impl(root_node, context, request).await {
        Ok(res) => Ok(res),
        Err(GraphQLRequestError::Invalid(err)) => {
            let message = format!("{:?}", err);
            let mut resp = new_response(StatusCode::BAD_REQUEST);
            *resp.body_mut() = Body::from(message);
            Ok(resp)
        }
        Err(err) => {
            let mut resp = new_response(StatusCode::INTERNAL_SERVER_ERROR);
            *resp.body_mut() = Body::from(format!("Server error."));
            println!("Server error: {:?}", err);
            Ok(resp)
        }
    }
}

async fn graphql_impl<CtxT, QueryT, MutationT, S>(
    root_node: Arc<RootNode<'static, QueryT, MutationT, S>>,
    context: Arc<CtxT>,
    request: Request<Body>,
) -> Result<Response<Body>, GraphQLRequestError>
where
    S: ScalarValue + Send + Sync + 'static,
    for<'b> &'b S: ScalarRefValue<'b>,
    CtxT: Send + Sync + 'static,
    QueryT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    MutationT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    QueryT::TypeInfo: Send + Sync,
    MutationT::TypeInfo: Send + Sync,
{
    match request.method() {
        &Method::GET => {
            let gql_req = request
                .uri()
                .query()
                .map(|q| gql_request_from_get(q).map(GraphQLRequest::Single))
                .unwrap_or_else(|| {
                    Err(GraphQLRequestError::Invalid(
                        "'query' parameter is missing".to_string(),
                    ))
                })?;
            Ok(execute_request(root_node, context, gql_req).await?)
        }
        &Method::POST => {
            let body = hyper::body::aggregate(request.into_body()).await?;
            let str_req = String::from_utf8(body.bytes().to_vec())?;
            let gql_req = serde_json::from_str::<GraphQLRequest<S>>(&str_req)?;
            Ok(execute_request(root_node, context, gql_req).await?)
        }
        _ => Ok(new_response(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

pub fn graphiql(graphql_endpoint: &str) -> Response<Body> {
    let mut resp = new_html_response(StatusCode::OK);
    // XXX: is the call to graphiql_source blocking?
    *resp.body_mut() = Body::from(juniper::graphiql::graphiql_source(graphql_endpoint));
    resp
}

pub fn playground(graphql_endpoint: &str) -> Response<Body> {
    let mut resp = new_html_response(StatusCode::OK);
    *resp.body_mut() = Body::from(juniper::http::playground::playground_source(
        graphql_endpoint,
    ));
    resp
}

async fn execute_request<CtxT, QueryT, MutationT, S>(
    root_node: Arc<RootNode<'static, QueryT, MutationT, S>>,
    context: Arc<CtxT>,
    request: GraphQLRequest<S>,
) -> Result<Response<Body>, GraphQLRequestError>
where
    S: ScalarValue + Send + Sync + 'static,
    for<'b> &'b S: ScalarRefValue<'b>,
    CtxT: Send + Sync + 'static,
    QueryT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    MutationT: GraphQLType<S, Context = CtxT> + Send + Sync + 'static,
    QueryT::TypeInfo: Send + Sync,
    MutationT::TypeInfo: Send + Sync,
{
    let (is_ok, body) = request.execute(root_node, context).await?;
    let code = if is_ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut resp = new_response(code);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *resp.body_mut() = body;
    Ok(resp)
}

fn gql_request_from_get<S>(input: &str) -> Result<JuniperGraphQLRequest<S>, GraphQLRequestError>
where
    S: ScalarValue,
{
    let mut query = None;
    let operation_name = None;
    let mut variables = None;
    for (key, value) in form_urlencoded::parse(input.as_bytes()).into_owned() {
        match key.as_ref() {
            "query" => {
                if query.is_some() {
                    return Err(invalid_err("query"));
                }
                query = Some(value)
            }
            "operationName" => {
                if operation_name.is_some() {
                    return Err(invalid_err("operationName"));
                }
            }
            "variables" => {
                if variables.is_some() {
                    return Err(invalid_err("variables"));
                }
                match serde_json::from_str::<InputValue<S>>(&value) {
                    Ok(parsed_variables) => variables = Some(parsed_variables),
                    Err(e) => return Err(e.into()),
                }
            }
            _ => continue,
        }
    }
    match query {
        Some(query) => Ok(JuniperGraphQLRequest::new(query, operation_name, variables)),
        None => Err(GraphQLRequestError::Invalid(
            "'query' parameter is missing".to_string(),
        )),
    }
}

fn invalid_err(parameter_name: &str) -> GraphQLRequestError {
    GraphQLRequestError::Invalid(format!(
        "'{}' parameter is specified multiple times",
        parameter_name
    ))
}

fn new_response(code: StatusCode) -> Response<Body> {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = code;
    r
}

fn new_html_response(code: StatusCode) -> Response<Body> {
    let mut resp = new_response(code);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

#[derive(serde_derive::Deserialize)]
#[serde(untagged)]
#[serde(bound = "InputValue<S>: Deserialize<'de>")]
enum GraphQLRequest<S = DefaultScalarValue>
where
    S: ScalarValue,
{
    Single(JuniperGraphQLRequest<S>),
    Batch(Vec<JuniperGraphQLRequest<S>>),
}

impl<S> GraphQLRequest<S>
where
    S: ScalarValue,
    for<'b> &'b S: ScalarRefValue<'b>,
{
    async fn execute<'a, CtxT: 'a, QueryT, MutationT>(
        self,
        root_node: Arc<RootNode<'a, QueryT, MutationT, S>>,
        context: Arc<CtxT>,
    ) -> Result<(bool, hyper::Body), GraphQLRequestError>
    where
        S: 'a,
        QueryT: GraphQLType<S, Context = CtxT> + 'a,
        MutationT: GraphQLType<S, Context = CtxT> + 'a,
    {
        match self {
            GraphQLRequest::Single(request) => {
                let res = request.execute(&root_node, &context);
                let is_ok = res.is_ok();
                let body = Body::from(serde_json::to_string_pretty(&res).unwrap());
                Ok((is_ok, body))
            }
            GraphQLRequest::Batch(requests) => {
                // // TODO: these clones are sad
                // let root_node = root_node.clone();
                // let context = context.clone();
                let results = requests
                    .into_iter()
                    .map(|request| {
                        let res = request.execute(&root_node, &context);
                        let is_ok = res.is_ok();
                        let body = serde_json::to_string_pretty(&res)?;
                        Ok((is_ok, body))
                    })
                    .collect::<Result<Vec<_>, GraphQLRequestError>>()?;
                let is_ok = results.iter().all(|&(is_ok, _)| is_ok);
                // concatenate json bodies as array
                // TODO: maybe use Body chunks instead?
                let bodies: Vec<_> = results.into_iter().map(|(_, body)| body).collect();
                let body = hyper::Body::from(format!("[{}]", bodies.join(",")));
                Ok((is_ok, body))
            }
        }
    }
}

/// GraphQL request error.
#[derive(Debug, Fail)]
enum GraphQLRequestError {
    /// Hyper error.
    #[fail(display = "hyper error: {:?}", _0)]
    Hyper(hyper::Error),

    /// Serde JSON error.
    #[fail(display = "serde json error: {:?}", _0)]
    SerdeJson(#[cause] serde_json::Error),

    /// String from UTF-8 error.
    #[fail(display = "from utf8 error: {:?}", _0)]
    FromUtf8(#[cause] std::string::FromUtf8Error),

    /// Invalid GraphQL query.
    #[fail(display = "Invalid Request: {:?}", _0)]
    Invalid(String),
}

err_converter!(Hyper, hyper::Error);
err_converter!(SerdeJson, serde_json::Error);
err_converter!(FromUtf8, std::string::FromUtf8Error);

#[macro_export]
macro_rules! err_converter {
    ( $a:ident, $b:ty ) => {
        impl From<$b> for GraphQLRequestError {
            fn from(e: $b) -> Self {
                GraphQLRequestError::$a(e)
            }
        }
    };
}
