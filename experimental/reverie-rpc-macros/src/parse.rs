/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use darling::FromMeta;
use heck::CamelCase;
use quote::format_ident;
use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::spanned::Spanned;

use crate::Method;
use crate::MethodAttrs;
use crate::Service;

fn parse_method(method: syn::TraitItemMethod, has_ref: &mut bool) -> syn::Result<Method> {
    if !method.sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            method.sig.generics.span(),
            "RPC methods cannot have generic parameters",
        ));
    }

    let ident = method.sig.ident;

    let camel_ident = syn::Ident::new(&ident.to_string().to_camel_case(), ident.span());

    // Search through the attributes and find any with the `rpc`
    // path. We need to exclude these from getting passed through
    // and expanded.
    let mut custom_attrs = None;
    #[allow(clippy::unnecessary_filter_map)]
    let attrs: Vec<_> = method
        .attrs
        .into_iter()
        .filter_map(|attrs| {
            // Clippy complains about this `filter_map` being
            // equivalent to `filter`, but it's not because `attrs`
            // needs to be passed by value to the closure so we can
            // move it out.
            if attrs.path.is_ident("rpc") {
                custom_attrs = Some(attrs);
                None
            } else {
                Some(attrs)
            }
        })
        .collect();

    let method_attrs = match custom_attrs {
        Some(custom_attrs) => {
            let meta = custom_attrs.parse_meta()?;
            MethodAttrs::from_meta(&meta)?
        }
        None => MethodAttrs::default(),
    };

    if method_attrs.no_response {
        if method.sig.output != syn::ReturnType::Default {
            return Err(syn::Error::new(
                method.sig.output.span(),
                "#[rpc(no_response)] methods cannot have a return type",
            ));
        }
    }

    let args = method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Receiver(_) => None,
            syn::FnArg::Typed(t) => {
                if let syn::Type::Reference(_) = t.ty.as_ref() {
                    *has_ref = true;
                }
                Some(t.clone())
            }
        })
        .collect();

    Ok(Method {
        attrs,
        method_attrs,
        ident,
        camel_ident,
        args,
        output: method.sig.output,
    })
}

impl Parse for Service {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let t: syn::ItemTrait = input.parse()?;

        let attrs = t.attrs;
        let vis = t.vis;
        let ident = t.ident;

        let mut has_ref = false;
        let mut methods = Vec::new();

        for inner in t.items {
            if let syn::TraitItem::Method(method) = inner {
                if method.sig.ident == "serve" {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("method conflicts with generated fn {}::serve", ident),
                    ));
                }

                methods.push(parse_method(method, &mut has_ref)?);
            }
        }

        let request_ident = format_ident!("{}Request", ident, span = ident.span());
        let response_ident = format_ident!("{}Response", ident, span = ident.span());
        let server_ident = format_ident!("Serve{}", ident, span = ident.span());
        let client_ident = format_ident!("{}Client", ident, span = ident.span());

        let request_generics = if has_ref {
            Some(syn::parse_quote!(<'req>))
        } else {
            None
        };

        Ok(Self {
            attrs,
            vis,
            ident,
            methods,
            request_ident,
            request_generics,
            response_ident,
            server_ident,
            client_ident,
        })
    }
}
