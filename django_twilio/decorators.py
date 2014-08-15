# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

"""
Useful decorators.
"""

import sys
import inspect
from functools import wraps

from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.http import (
    HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed)
from django.utils.decorators import method_decorator

from twilio.twiml import Verb
from twilio.util import RequestValidator

from .settings import TWILIO_AUTH_TOKEN
from .utils import get_blacklisted_response


# Snippet from the `six` library to help with Python3 compatibility
if sys.version_info[0] == 3:
    text_type = str
else:
    text_type = unicode


def twilio_view(thing):
    """
    This decorator provides several helpful shortcuts for writing Twilio views.

        - It ensures that only requests from Twilio are passed through. This
          helps protect you from forged requests.

        - It ensures your view is exempt from CSRF checks via Django's
          @csrf_exempt decorator. This is necessary for any view that accepts
          POST requests from outside the local domain (eg: Twilio's servers).

        - It enforces the blacklist. If you've got any ``Caller``s who are
          blacklisted, any requests from them will be rejected.

        - It allows your view to (optionally) return TwiML to pass back to
          Twilio's servers instead of building an ``HttpResponse`` object
          manually.

        - It allows your view to (optionally) return any ``twilio.Verb`` object
          instead of building a ``HttpResponse`` object manually.

          .. note::
            The forgery protection checks ONLY happen if ``settings.DEBUG =
            False`` (aka, your site is in production).

    Usage::

        from twilio import twiml

        @twilio_view
        def my_view(request):
            r = twiml.Response()
            r.message('Thanks for the SMS message!')
            return r
    """

    # Decorate class-based views
    if isinstance(thing, type) and issubclass(thing, View):
        _twilio_method_decorator = method_decorator(_twilio_function_view)
        thing.dispatch = _twilio_method_decorator(thing.dispatch)
        decorated_thing = thing

    # Decorate methods of class-based views
    elif inspect.ismethod(thing):
        _twilio_method_decorator = method_decorator(_twilio_function_view)
        decorated_thing = _twilio_method_decorator(thing)

    # Decorate function views
    else:
        decorated_thing = _twilio_function_view(thing)

    return decorated_thing


def _twilio_function_view(f):

    @csrf_exempt
    @wraps(f)
    def decorated_view(request, *args, **kwargs):

        assert isinstance(request, HttpRequest)

        # Turn off Twilio authentication when explicitly requested, or
        # in debug mode. Otherwise things do not work properly. For
        # more information, see the docs.
        use_forgery_protection = getattr(
            settings,
            'DJANGO_TWILIO_FORGERY_PROTECTION',
            not settings.DEBUG,
        )
        if use_forgery_protection:

            if request.method not in ['GET', 'POST']:
                return HttpResponseNotAllowed(request.method)

            # Forgery check
            try:
                validator = RequestValidator(TWILIO_AUTH_TOKEN)
                url = request.build_absolute_uri()
                signature = request.META['HTTP_X_TWILIO_SIGNATURE']
            except (AttributeError, KeyError):
                return HttpResponseForbidden()

            if request.method == 'POST':
                if not validator.validate(url, request.POST, signature):
                    return HttpResponseForbidden()
            elif request.method == 'GET':
                if not validator.validate(url, request.GET, signature):
                    return HttpResponseForbidden()

        # Blacklist check, by default is true
        check_blacklist = getattr(
            settings,
            'DJANGO_TWILIO_BLACKLIST_CHECK',
            True
        )
        if check_blacklist:
            blacklisted_resp = get_blacklisted_response(request)
            if blacklisted_resp:
                return blacklisted_resp

        response = f(request, *args, **kwargs)

        if isinstance(response, (text_type, bytes)):
            return HttpResponse(response, content_type='application/xml')
        elif isinstance(response, Verb):
            return HttpResponse(str(response), content_type='application/xml')
        else:
            return response

    return decorated_view
