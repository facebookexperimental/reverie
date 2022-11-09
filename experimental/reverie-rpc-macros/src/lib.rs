/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

extern crate proc_macro;

mod expand;
mod parse;

use proc_macro::TokenStream;
use quote::ToTokens;

struct Service {
    attrs: Vec<syn::Attribute>,
    vis: syn::Visibility,
    ident: syn::Ident,
    methods: Vec<Method>,
    request_ident: syn::Ident,
    request_generics: Option<syn::Generics>,
    response_ident: syn::Ident,
    server_ident: syn::Ident,
    client_ident: syn::Ident,
}

#[derive(Default, Debug, darling::FromMeta)]
struct MethodAttrs {
    /// True if `#[rpc(no_response)]` was specified.
    #[darling(default)]
    no_response: bool,
}

struct Method {
    /// Attributes that should get expanded.
    attrs: Vec<syn::Attribute>,
    /// Attributes that only we care about (e.g., `#[rpc(no_response = true)]`)
    method_attrs: MethodAttrs,
    /// The method name.
    ident: syn::Ident,
    /// The camel-case version of the method name. Used for generating the
    /// Request and Response enum variants.
    camel_ident: syn::Ident,
    // NOTE: We expect all methods to take &self implicitly.
    args: Vec<syn::PatType>,
    /// Return type of the method.
    output: syn::ReturnType,
}

#[proc_macro_attribute]
pub fn service(_args: TokenStream, input: TokenStream) -> TokenStream {
    let service = syn::parse_macro_input!(input as Service);
    service.into_token_stream().into()
}
