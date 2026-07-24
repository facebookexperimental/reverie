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

struct Tool {
    outer_item: syn::ItemImpl,
    detoured_methods: Vec<Detour>,
}

#[derive(Default, Debug, darling::FromMeta)]
struct DetourAttrs {
    func: String,
    lib: String,
}

struct Detour {
    callback_name: syn::Ident,
    stub_name: syn::Ident,
    undetoured_field_name: syn::Ident,
    undetoured_method_name: syn::Ident,
    detoured_definition_name: syn::Ident,
    detoured_function_type_name: syn::Ident,
    attrs: DetourAttrs,
    outer_item: syn::ImplItemMethod,
}

#[proc_macro_attribute]
pub fn tool(_args: TokenStream, input: TokenStream) -> TokenStream {
    let service = syn::parse_macro_input!(input as Tool);
    service.into_token_stream().into()
}
